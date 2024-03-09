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

package com.webauthn4j.metadata.legacy;

import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.jws.JWS;
import com.webauthn4j.data.jws.JWSFactory;
import com.webauthn4j.metadata.HttpClient;
import com.webauthn4j.metadata.SimpleHttpClient;
import com.webauthn4j.metadata.exception.MDSException;
import com.webauthn4j.metadata.legacy.data.MetadataItem;
import com.webauthn4j.metadata.legacy.data.MetadataItemImpl;
import com.webauthn4j.metadata.legacy.data.statement.MetadataStatement;
import com.webauthn4j.metadata.legacy.data.toc.MetadataTOCPayload;
import com.webauthn4j.metadata.legacy.data.toc.MetadataTOCPayloadEntry;
import com.webauthn4j.metadata.legacy.validator.MetadataStatementValidator;
import com.webauthn4j.util.Base64UrlUtil;
import com.webauthn4j.util.CertificateUtil;
import com.webauthn4j.util.MessageDigestUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.cert.*;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.*;
import java.util.stream.Collectors;

@Deprecated
public class FidoMdsMetadataItemsProvider implements MetadataItemsProvider {

    private static final String DEFAULT_FIDO_METADATA_SERVICE_ENDPOINT = "https://mds2.fidoalliance.org/";
    private final Logger logger = LoggerFactory.getLogger(FidoMdsMetadataItemsProvider.class);
    private final JsonConverter jsonConverter;
    private final JWSFactory jwsFactory;
    private final HttpClient httpClient;
    private final TrustAnchor trustAnchor;
    private final MetadataStatementValidator metadataStatementValidator = new MetadataStatementValidator();
    private final String token;
    Map<AAGUID, Set<MetadataItem>> cachedMetadataItemMap;
    OffsetDateTime nextUpdate;
    OffsetDateTime lastRefresh;
    private String fidoMetadataServiceEndpoint = DEFAULT_FIDO_METADATA_SERVICE_ENDPOINT;

    public FidoMdsMetadataItemsProvider(ObjectConverter objectConverter, String token, HttpClient httpClient, X509Certificate rootCertificate) {
        this.jsonConverter = objectConverter.getJsonConverter();
        this.jwsFactory = new JWSFactory(objectConverter);
        this.token = token;
        this.httpClient = httpClient;
        this.trustAnchor = new TrustAnchor(rootCertificate, null);
    }

    public FidoMdsMetadataItemsProvider(ObjectConverter objectConverter, String token, HttpClient httpClient, Path path) {
        this(objectConverter, token, httpClient, loadRootCertificateFromPath(path));
    }

    public FidoMdsMetadataItemsProvider(ObjectConverter objectConverter, HttpClient httpClient, X509Certificate rootCertificate) {
        this(objectConverter, null, httpClient, rootCertificate);
    }

    public FidoMdsMetadataItemsProvider(ObjectConverter objectConverter, HttpClient httpClient, Path path) {
        this(objectConverter, null, httpClient, path);
    }

    public FidoMdsMetadataItemsProvider(ObjectConverter objectConverter, X509Certificate x509Certificate) {
        this(objectConverter, new SimpleHttpClient(), x509Certificate);
    }

    private static X509Certificate loadRootCertificateFromPath(Path path) {
        try {
            InputStream inputStream = Files.newInputStream(path);
            return CertificateUtil.generateX509Certificate(inputStream);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    static String appendToken(String url, String token) {
        if (url == null) {
            throw new IllegalArgumentException("url must not be null.");
        }
        if (token == null) {
            return url;
        }
        try {
            URI uriObject = new URI(url);
            String query = uriObject.getQuery();
            if (query == null) {
                query = "token=" + token;
            }
            else {
                query += "&" + "token=" + token;
            }
            return new URI(uriObject.getScheme(), uriObject.getAuthority(),
                    uriObject.getPath(), query, uriObject.getFragment()).toString();
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException(String.format("Provided url %s is illegal.", url), e);
        }
    }

    @Override
    public Map<AAGUID, Set<MetadataItem>> provide() {
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

    private void refresh() {
        MetadataTOCPayload tocPayload = fetchMetadataTOCPayload(false);

        cachedMetadataItemMap =
                tocPayload.getEntries().parallelStream().map(entry -> {
                    try {
                        return fetchFidoMdsMetadataItem(entry);
                    } catch (RuntimeException e) {
                        logger.warn("Failed to fetch MetadataTOCPayLoad", e);
                        return null;
                    }
                })
                        .filter(Objects::nonNull)
                        .distinct()
                        .collect(Collectors.groupingBy(MetadataItem::getAaguid))
                        .entrySet()
                        .stream()
                        .collect(Collectors.toMap(Map.Entry::getKey, entry -> Collections.unmodifiableSet(new HashSet<>(entry.getValue()))));

        nextUpdate = tocPayload.getNextUpdate().atStartOfDay().atOffset(ZoneOffset.UTC);
        lastRefresh = OffsetDateTime.now(ZoneOffset.UTC);
    }

    boolean needsRefresh() {
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        return cachedMetadataItemMap == null || (nextUpdate.isBefore(now) && lastRefresh.isBefore(now.minusHours(1)));
    }

    /**
     * fetch MetaDataTOCPayload
     *
     * @param skipCertPathValidation certPath Validation shouldn't be off except testing
     * @return MetaDataTOCPayload
     */
    MetadataTOCPayload fetchMetadataTOCPayload(boolean skipCertPathValidation) {
        String uriWithToken = appendToken(fidoMetadataServiceEndpoint, token);

        String toc = httpClient.fetch(uriWithToken);

        JWS<MetadataTOCPayload> jws = jwsFactory.parse(toc, MetadataTOCPayload.class);
        if (!jws.isValidSignature()) {
            throw new MDSException("invalid signature");
        }
        if (!skipCertPathValidation) {
            validateCertPath(jws);
        }
        return jws.getPayload();
    }

    private MetadataItem fetchFidoMdsMetadataItem(MetadataTOCPayloadEntry entry) {
        MetadataStatement metadataStatement = fetchMetadataStatement(entry.getUrl().toString(), Base64UrlUtil.decode(entry.getHash()));
        return new MetadataItemImpl(
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
        CertPath certPath = jws.getHeader().getX5c();

        CertPathValidator certPathValidator = CertificateUtil.createCertPathValidator();
        PKIXParameters certPathParameters = CertificateUtil.createPKIXParameters(trustAnchors);
        PKIXRevocationChecker pkixRevocationChecker = (PKIXRevocationChecker) certPathValidator.getRevocationChecker();
        pkixRevocationChecker.setOptions(EnumSet.of(PKIXRevocationChecker.Option.PREFER_CRLS));
        certPathParameters.addCertPathChecker(pkixRevocationChecker);

        try {
            certPathValidator.validate(certPath, certPathParameters);
        } catch (InvalidAlgorithmParameterException e) {
            throw new MDSException("invalid algorithm parameter", e);
        } catch (CertPathValidatorException e) {
            throw new MDSException("invalid cert path", e);
        }
    }

    MetadataStatement fetchMetadataStatement(String uri, byte[] expectedHash) {
        String uriWithToken = appendToken(uri, token);
        String metadataStatementBase64url = httpClient.fetch(uriWithToken);
        String metadataStatementStr = new String(Base64UrlUtil.decode(metadataStatementBase64url));
        byte[] hash = MessageDigestUtil.createSHA256().digest(metadataStatementBase64url.getBytes(StandardCharsets.UTF_8));
        // As hash is known data to statement provider, there is no risk of timing attack and it is OK to use `Arrays.equals` instead of `MessageDigest.isEqual` here.
        if (!Arrays.equals(hash, expectedHash)) {
            throw new MDSException("Hash of metadataStatement doesn't match");
        }
        MetadataStatement metadataStatement = jsonConverter.readValue(metadataStatementStr, MetadataStatement.class);
        metadataStatementValidator.validate(metadataStatement);
        return metadataStatement;
    }

}
