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

package net.sharplab.springframework.security.webauthn.anchor;

import net.sharplab.springframework.security.fido.metadata.FIDOMetadataServiceClient;
import net.sharplab.springframework.security.fido.metadata.Metadata;
import net.sharplab.springframework.security.fido.metadata.structure.MetadataStatement;
import net.sharplab.springframework.security.fido.metadata.structure.MetadataTOCPayload;
import net.sharplab.springframework.security.fido.metadata.structure.MetadataTOCPayloadEntry;
import net.sharplab.springframework.security.webauthn.attestation.statement.FIDOU2FAttestationStatement;
import net.sharplab.springframework.security.webauthn.attestation.statement.WebAuthnAttestationStatement;
import net.sharplab.springframework.security.webauthn.util.CertificateUtil;

import java.security.InvalidAlgorithmParameterException;
import java.security.cert.*;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * FIDO Metadata Service backed TrustAnchorService
 */
public class FIDOMetadataServiceTrustAnchorService {

    private FIDOMetadataServiceClient fidoMetadataServiceClient;

    Map<TrustAnchor, Metadata> cachedMetadataMap;
    LocalDate nextUpdate;
    LocalDateTime lastRefresh;

    public FIDOMetadataServiceTrustAnchorService(FIDOMetadataServiceClient fidoMetadataServiceClient) {
        this.fidoMetadataServiceClient = fidoMetadataServiceClient;
    }

    public Metadata findMetadata(WebAuthnAttestationStatement attestationStatement) {
        FIDOU2FAttestationStatement fidoU2FAttestationStatement = (FIDOU2FAttestationStatement) attestationStatement;
        CertPath certPath = fidoU2FAttestationStatement.getX5c();
        Map<TrustAnchor, Metadata> metadataMap = getMetadataMap();

        Set<TrustAnchor> trustAnchors = metadataMap.keySet();

        CertPathValidator certPathValidator = CertificateUtil.generateCertPathValidator();
        PKIXParameters certPathParameters = CertificateUtil.generatePKIXParameters(trustAnchors);
        certPathParameters.setRevocationEnabled(false);

        PKIXCertPathBuilderResult result;
        try {
            result = (PKIXCertPathBuilderResult) certPathValidator.validate(certPath, certPathParameters);
        } catch (InvalidAlgorithmParameterException e) {
            throw new IllegalStateException(e);
        } catch (CertPathValidatorException e) {
            return null;
        }

        return metadataMap.get(result.getTrustAnchor());
    }

    public Map<TrustAnchor, Metadata> getMetadataMap() {
        if (needsRefresh()) {
            cachedMetadataMap = refreshMetadataMap();
        }
        return cachedMetadataMap;
    }

    boolean needsRefresh() {
        return cachedMetadataMap == null || (!nextUpdate.isAfter(LocalDate.now()) && lastRefresh.isBefore(LocalDateTime.now().minusHours(1)));
    }

    Map<TrustAnchor, Metadata> refreshMetadataMap() {
        MetadataTOCPayload metadataTOC = fidoMetadataServiceClient.retrieveMetadataTOC();
        List<MetadataTOCPayloadEntry> entries = metadataTOC.getEntries();

        Map<TrustAnchor, Metadata> metadataMap = new HashMap<>();

        for (MetadataTOCPayloadEntry entry : entries) {
            MetadataStatement metadataStatement = fidoMetadataServiceClient.retrieveMetadataStatement(entry.getUrl());
            Metadata metadata = new Metadata();
            metadata.setAaid(entry.getAaid());
            metadata.setHash(entry.getHash());
            metadata.setStatusReports(entry.getStatusReports());
            metadata.setTimeOfLastStatusChange(entry.getTimeOfLastStatusChange());
            metadata.setAttestationCertificateKeyIdentifiers(entry.getAttestationCertificateKeyIdentifiers());
            metadata.setMetadataStatement(metadataStatement);
            for (X509Certificate certificate : metadataStatement.getAttestationRootCertificates()) {
                metadataMap.put(new TrustAnchor(certificate, null), metadata);
            }
        }
        nextUpdate = metadataTOC.getNextUpdate();
        lastRefresh = LocalDateTime.now();
        return metadataMap;
    }

}
