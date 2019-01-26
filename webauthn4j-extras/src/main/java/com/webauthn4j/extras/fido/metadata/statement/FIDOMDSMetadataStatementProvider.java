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

package com.webauthn4j.extras.fido.metadata.statement;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.extras.fido.metadata.FIDOMDSClient;
import com.webauthn4j.extras.fido.metadata.Metadata;
import com.webauthn4j.extras.fido.metadata.exception.MDSException;
import com.webauthn4j.extras.fido.metadata.toc.MetadataTOCPayload;
import com.webauthn4j.registry.Registry;
import com.webauthn4j.response.attestation.authenticator.AAGUID;
import com.webauthn4j.util.CertificateUtil;
import com.webauthn4j.util.WIP;
import com.webauthn4j.util.exception.NotImplementedException;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@WIP
public class FIDOMDSMetadataStatementProvider implements MetadataStatementProvider {

    private JsonConverter jsonConverter;
    private FIDOMDSClient fidoMDSClient;

    Map<AAGUID, List<Metadata>> cachedMetadataMap;
    OffsetDateTime nextUpdate;
    OffsetDateTime lastRefresh;

    private PublicKey publicKey;

    public FIDOMDSMetadataStatementProvider(Registry registry, FIDOMDSClient fidoMDSClient, PublicKey publicKey) {
        this.jsonConverter = new JsonConverter(registry.getJsonMapper());
        this.fidoMDSClient = fidoMDSClient;
        this.publicKey = publicKey;
    }

    public FIDOMDSMetadataStatementProvider(Registry registry, FIDOMDSClient fidoMDSClient, Path path) {
        this(registry, fidoMDSClient, loadPublicKeyFromPath(path));
    }

    public FIDOMDSMetadataStatementProvider(Registry registry, FIDOMDSClient fidoMDSClient) {
        this(registry, fidoMDSClient, loadPublicKeyFromEmbeddedCertificate());
    }

    @Override
    public Map<AAGUID, List<MetadataStatement>> provide() {
        if (needsRefresh()) {
            refresh();
        }
        return cachedMetadataMap.entrySet()
                .stream()
                .filter(entry -> true) //TODO
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        entry -> entry.getValue().stream().map(Metadata::getMetadataStatement).collect(Collectors.toList())
                ));
    }

    void refresh(){
        MetadataTOCPayload tocPayload = fetchMetadataTOCPayload();

        cachedMetadataMap =
        tocPayload.getEntries().parallelStream().map(entry ->{
            MetadataStatement metadataStatement = fetchMetadataStatement(entry.getUrl());
            Metadata metadata = new Metadata();
            metadata.setAaid(entry.getAaid());
            metadata.setAaguid(new AAGUID(entry.getAaguid()));
            metadata.setHash(entry.getHash());
            metadata.setStatusReports(entry.getStatusReports());
            metadata.setTimeOfLastStatusChange(entry.getTimeOfLastStatusChange());
            metadata.setAttestationCertificateKeyIdentifiers(entry.getAttestationCertificateKeyIdentifiers());
            metadata.setMetadataStatement(metadataStatement);
            return metadata;
        })
        .collect(Collectors.groupingBy(Metadata::getAaguid));

        nextUpdate = tocPayload.getNextUpdate();
        lastRefresh = OffsetDateTime.now(ZoneOffset.UTC);
    }

    boolean needsRefresh() {
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        return cachedMetadataMap == null || (!nextUpdate.isAfter(now) && lastRefresh.isBefore(now.minusHours(1)));
    }

    private MetadataTOCPayload fetchMetadataTOCPayload(){
        String toc = fidoMDSClient.fetchMetadataTOC();

        SignedJWT jwt;
        try {
            jwt = (SignedJWT) JWTParser.parse(toc);
        } catch (ParseException e) {
            throw new MDSException(e);
        }


        JWSVerifier jwsVerifier;
        try {
            if(publicKey instanceof ECPublicKey){
                jwsVerifier = new ECDSAVerifier((ECPublicKey) publicKey);
            }
            else if(publicKey instanceof RSAPublicKey){
                jwsVerifier = new RSASSAVerifier((RSAPublicKey) publicKey);
            }
            else {
                throw new NotImplementedException();
            }
            jwt.verify(jwsVerifier);
        } catch (JOSEException e) {
            throw new MDSException(e);
        }

        String payloadString = jwt.getPayload().toString();
        return jsonConverter.readValue(payloadString, MetadataTOCPayload.class);
    }

    private MetadataStatement fetchMetadataStatement(URI uri) {
        String metadataStatementStr = fidoMDSClient.fetchMetadataStatement(uri);
        return jsonConverter.readValue(metadataStatementStr, MetadataStatement.class);
    }

    private static PublicKey loadPublicKeyFromPath(Path path) {
        try {
            InputStream inputStream = Files.newInputStream(path);
            X509Certificate certificate = CertificateUtil.generateX509Certificate(inputStream);
            return certificate.getPublicKey();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static PublicKey loadPublicKeyFromEmbeddedCertificate() {
        InputStream inputStream = FIDOMDSMetadataStatementProvider.class.getClassLoader()
                .getResourceAsStream("metadata/certs/FIDOMetadataService.cer");
        X509Certificate certificate = CertificateUtil.generateX509Certificate(inputStream);
        return certificate.getPublicKey();
    }

}
