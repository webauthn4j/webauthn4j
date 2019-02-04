/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webauthn4j.extras.fido.metadata;

import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.extras.fido.metadata.exception.MDSException;
import com.webauthn4j.extras.fido.metadata.toc.MetadataTOCPayload;
import com.webauthn4j.extras.fido.metadata.toc.MetadataTOCPayloadEntry;
import com.webauthn4j.registry.Registry;
import com.webauthn4j.response.attestation.authenticator.AAGUID;
import com.webauthn4j.util.Base64UrlUtil;
import com.webauthn4j.util.CertificateUtil;
import com.webauthn4j.util.MessageDigestUtil;
import com.webauthn4j.util.jws.JWS;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.cert.*;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.*;
import java.util.stream.Collectors;

public class FidoMdsMetadataItemListProvider implements MetadataItemListProvider<FidoMdsMetadataItem> {

    private static final String DEFAULT_FIDO_METADATA_SERVICE_ENDPOINT = "https://mds2.fidoalliance.org/";

    private Registry registry;
    private HttpClient httpClient;

    private String fidoMetadataServiceEndpoint = DEFAULT_FIDO_METADATA_SERVICE_ENDPOINT;

    Map<AAGUID, List<FidoMdsMetadataItem>> cachedMetadataItemMap;
    OffsetDateTime nextUpdate;
    OffsetDateTime lastRefresh;

    private TrustAnchor trustAnchor;

    public FidoMdsMetadataItemListProvider(Registry registry, HttpClient httpClient, X509Certificate rootCertificate) {
        this.registry = registry;
        this.httpClient = httpClient;
        this.trustAnchor = new TrustAnchor(rootCertificate, null);
    }

    public FidoMdsMetadataItemListProvider(Registry registry, HttpClient httpClient, Path path) {
        this(registry, httpClient, loadRootCertificateFromPath(path));
    }

    public FidoMdsMetadataItemListProvider(Registry registry, HttpClient httpClient) {
        this(registry, httpClient, loadEmbeddedFidoMdsRootCertificate());
    }

    public FidoMdsMetadataItemListProvider(Registry registry) {
        this(registry, new SimpleHttpClient(), loadEmbeddedFidoMdsRootCertificate());
    }

    @Override
    public Map<AAGUID, List<FidoMdsMetadataItem>> provide() {
        if (needsRefresh()) {
            refresh();
        }
        return cachedMetadataItemMap;
    }


    public String getFidoMetadataServiceEndpoint() {
        return fidoMetadataServiceEndpoint;
    }

    public void setFidoMetadataServiceEndpoint(String fidoMetadataServiceEndpoint) {
        this.fidoMetadataServiceEndpoint = fidoMetadataServiceEndpoint;
    }

    private void refresh(){
        MetadataTOCPayload tocPayload = fetchMetadataTOCPayload();

        cachedMetadataItemMap =
        tocPayload.getEntries().parallelStream().map(this::mapToFidoMdsMetadataItem)
        .collect(Collectors.groupingBy(item -> new AAGUID(item.getMetadataStatement().getAaguid())));

        nextUpdate = tocPayload.getNextUpdate().atStartOfDay().atOffset(ZoneOffset.UTC);
        lastRefresh = OffsetDateTime.now(ZoneOffset.UTC);
    }

    boolean needsRefresh() {
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        return cachedMetadataItemMap == null || (nextUpdate.isBefore(now) && lastRefresh.isBefore(now.minusHours(1)));
    }

    MetadataTOCPayload fetchMetadataTOCPayload(){
        String url = fidoMetadataServiceEndpoint;
        String toc = httpClient.fetch(url);

        JWS<MetadataTOCPayload> jws = JWS.parse(toc, registry, MetadataTOCPayload.class);
        if(!jws.isValidSignature()){
            throw new MDSException("invalid signature");
        }
        validateCertPath(jws);
        return jws.getPayload();
    }

    private FidoMdsMetadataItem mapToFidoMdsMetadataItem(MetadataTOCPayloadEntry entry) {
        MetadataStatement metadataStatement = fetchMetadataStatement(entry.getUrl(), Base64UrlUtil.decode(entry.getHash()));
        return new FidoMdsMetadataItemImpl(
                entry.getAaid(),
                new AAGUID(entry.getAaguid()),
                entry.getAttestationCertificateKeyIdentifiers(),
                entry.getHash(),
                entry.getStatusReports(),
                entry.getTimeOfLastStatusChange(),
                metadataStatement
        );
    }

    private void validateCertPath(JWS<MetadataTOCPayload> jws) {
        Set<TrustAnchor> trustAnchors = Collections.singleton(trustAnchor);
        CertPath certPath = jws.getHeader().getX5c().createCertPath();

        CertPathValidator certPathValidator = CertificateUtil.createCertPathValidator();
        PKIXParameters certPathParameters = CertificateUtil.createPKIXParameters(trustAnchors);

        try {
            certPathValidator.validate(certPath, certPathParameters);
        } catch (InvalidAlgorithmParameterException e) {
            throw new MDSException("invalid algorithm parameter", e);
        } catch (CertPathValidatorException e) {
            throw new MDSException("invalid cert path", e);
        }
    }

    private MetadataStatement fetchMetadataStatement(URI uri, byte[] expectedHash) {
        String metadataStatementBase64url = httpClient.fetch(uri.toString());
        String metadataStatementStr = new String(Base64UrlUtil.decode(metadataStatementBase64url));
        byte[] hash = MessageDigestUtil.createSHA256().digest(metadataStatementStr.getBytes());
        if(!Arrays.equals(hash, expectedHash)){
            throw new MDSException("Hash of metadataStatement doesn't match");
        }
        return new JsonConverter(registry.getJsonMapper()).readValue(metadataStatementStr, MetadataStatement.class);
    }

    private static X509Certificate loadRootCertificateFromPath(Path path) {
        try {
            InputStream inputStream = Files.newInputStream(path);
            return CertificateUtil.generateX509Certificate(inputStream);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static X509Certificate loadEmbeddedFidoMdsRootCertificate() {
        InputStream inputStream = FidoMdsMetadataItemListProvider.class.getClassLoader()
                .getResourceAsStream("metadata/certs/FIDOMetadataService.cer");
        return CertificateUtil.generateX509Certificate(inputStream);
    }

}
