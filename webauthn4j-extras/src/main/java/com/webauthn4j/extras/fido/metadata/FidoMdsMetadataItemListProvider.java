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
import com.webauthn4j.util.exception.UnexpectedCheckedException;
import com.webauthn4j.util.jws.JWS;
import com.webauthn4j.util.jws.JWSHeader;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.cert.*;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class FidoMdsMetadataItemListProvider implements MetadataItemListProvider {

    private static final URL DEFAULT_FIDO_METADATA_SERVICE_ENDPOINT;

    private JsonConverter jsonConverter;
    private HttpClient httpClient;

    private URL fidoMetadataServiceEndpoint = DEFAULT_FIDO_METADATA_SERVICE_ENDPOINT;

    Map<AAGUID, List<FidoMdsMetadataItem>> cachedMetadataItemMap;
    OffsetDateTime nextUpdate;
    OffsetDateTime lastRefresh;

    private TrustAnchor trustAnchor;

    static {
        try {
            DEFAULT_FIDO_METADATA_SERVICE_ENDPOINT = new URL("https://mds2.fidoalliance.org/");
        } catch (MalformedURLException e) {
            throw new UnexpectedCheckedException(e);
        }
    }

    public FidoMdsMetadataItemListProvider(Registry registry, HttpClient httpClient, X509Certificate rootCertificate) {
        this.jsonConverter = new JsonConverter(registry.getJsonMapper());
        this.httpClient = httpClient;
        this.trustAnchor = new TrustAnchor(rootCertificate, null);
    }

    public FidoMdsMetadataItemListProvider(Registry registry, HttpClient httpClient, Path path) {
        this(registry, httpClient, loadRootCertificateFromPath(path));
    }

    public FidoMdsMetadataItemListProvider(Registry registry, HttpClient httpClient) {
        this(registry, httpClient, loadEmbeddedCertificate());
    }

    public FidoMdsMetadataItemListProvider(Registry registry) {
        this(registry, new SimpleHttpClient(), loadEmbeddedCertificate());
    }

    @Override
    public Map<AAGUID, List<FidoMdsMetadataItem>> provide() {
        if (needsRefresh()) {
            refresh();
        }
        return cachedMetadataItemMap;
    }

    void refresh(){
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
        String url = fidoMetadataServiceEndpoint.toString();
        String toc = httpClient.fetch(url);

        JWS<MetadataTOCPayload> jws = parseJWS(toc);
        if(!jws.isValidSignature()){
            throw new MDSException("invalid signature");
        }
        validateCertPath(jws);
        return jws.getPayload();
    }

    private FidoMdsMetadataItem mapToFidoMdsMetadataItem(MetadataTOCPayloadEntry entry) {
        MetadataStatement metadataStatement = fetchMetadataStatement(entry.getUrl());
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
        certPathParameters.setRevocationEnabled(false);

        try {
            certPathValidator.validate(certPath, certPathParameters);
        } catch (InvalidAlgorithmParameterException e) {
            throw new MDSException("invalid algorithm parameter", e);
        } catch (CertPathValidatorException e) {
            throw new MDSException("invalid cert path", e);
        }
    }

    private MetadataStatement fetchMetadataStatement(URI uri) {
        String metadataStatementBase64url = httpClient.fetch(uri.toString());
        String metadataStatementStr = new String(Base64UrlUtil.decode(metadataStatementBase64url));
        return jsonConverter.readValue(metadataStatementStr, MetadataStatement.class);
    }

    private JWS<MetadataTOCPayload> parseJWS(String value){
        String[] data = value.split("\\.");
        if (data.length != 3) {
            throw new IllegalArgumentException("Invalid JWS");
        }
        String headerString = data[0];
        String payloadString = data[1];
        String signatureString = data[2];
        JWSHeader header = jsonConverter.readValue(new String(Base64UrlUtil.decode(headerString), StandardCharsets.UTF_8), JWSHeader.class);
        MetadataTOCPayload payload = jsonConverter.readValue(new String(Base64UrlUtil.decode(payloadString), StandardCharsets.UTF_8), MetadataTOCPayload.class);
        byte[] signature = Base64UrlUtil.decode(signatureString);
        return new JWS<>(header, headerString, payload, payloadString, signature);
    }

    private static X509Certificate loadRootCertificateFromPath(Path path) {
        try {
            InputStream inputStream = Files.newInputStream(path);
            return CertificateUtil.generateX509Certificate(inputStream);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static X509Certificate loadEmbeddedCertificate() {
        InputStream inputStream = FidoMdsMetadataItemListProvider.class.getClassLoader()
                .getResourceAsStream("metadata/certs/FIDOMetadataService.cer");
        return CertificateUtil.generateX509Certificate(inputStream);
    }

}
