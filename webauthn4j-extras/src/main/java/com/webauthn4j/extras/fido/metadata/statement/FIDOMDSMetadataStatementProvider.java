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

import com.webauthn4j.extras.fido.metadata.FIDOMDSClient;
import com.webauthn4j.extras.fido.metadata.Metadata;
import com.webauthn4j.extras.fido.metadata.toc.MetadataTOCPayload;
import com.webauthn4j.extras.fido.metadata.toc.MetadataTOCPayloadEntry;
import com.webauthn4j.response.attestation.statement.AttestationCertificatePath;
import com.webauthn4j.response.attestation.statement.CertificateBaseAttestationStatement;
import com.webauthn4j.util.CertificateUtil;
import com.webauthn4j.util.WIP;
import com.webauthn4j.util.exception.NotImplementedException;

import java.security.InvalidAlgorithmParameterException;
import java.security.cert.*;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

@WIP
public class FIDOMDSMetadataStatementProvider implements MetadataStatementProvider {

    private FIDOMDSClient fidoMDSClient;

    Map<TrustAnchor, Metadata> cachedMetadataMap;
    LocalDate nextUpdate;
    LocalDateTime lastRefresh;

    public FIDOMDSMetadataStatementProvider(FIDOMDSClient fidoMDSClient) {
        this.fidoMDSClient = fidoMDSClient;
    }

    @Override
    public Map<byte[], List<MetadataStatement>> provide() {
        MetadataTOCPayload toc = fidoMDSClient.retrieveMetadataTOC();
        throw new NotImplementedException();
    }

    Metadata findMetadata(CertificateBaseAttestationStatement attestationStatement) {
        AttestationCertificatePath attestationCertificatePath = attestationStatement.getX5c();
        Map<TrustAnchor, Metadata> metadataMap = getMetadataMap();

        Set<TrustAnchor> trustAnchors = metadataMap.keySet();

        CertPathValidator certPathValidator = CertificateUtil.createCertPathValidator();
        PKIXParameters certPathParameters = CertificateUtil.createPKIXParameters(trustAnchors);
        certPathParameters.setRevocationEnabled(false);

        PKIXCertPathBuilderResult result;
        try {
            result = (PKIXCertPathBuilderResult) certPathValidator.validate(attestationCertificatePath.createCertPath(), certPathParameters);
        } catch (InvalidAlgorithmParameterException e) {
            throw new IllegalStateException(e);
        } catch (CertPathValidatorException e) {
            return null;
        }

        return metadataMap.get(result.getTrustAnchor());
    }

    Map<TrustAnchor, Metadata> getMetadataMap() {
        if (needsRefresh()) {
            cachedMetadataMap = refreshMetadataMap();
        }
        return cachedMetadataMap;
    }

    boolean needsRefresh() {
        return cachedMetadataMap == null || (!nextUpdate.isAfter(LocalDate.now()) && lastRefresh.isBefore(LocalDateTime.now().minusHours(1)));
    }

    Map<TrustAnchor, Metadata> refreshMetadataMap() {
        MetadataTOCPayload metadataTOC = fidoMDSClient.retrieveMetadataTOC();
        List<MetadataTOCPayloadEntry> entries = metadataTOC.getEntries();

        Map<TrustAnchor, Metadata> metadataMap = new HashMap<>();

        for (MetadataTOCPayloadEntry entry : entries) {
            MetadataStatement metadataStatement = fidoMDSClient.retrieveMetadataStatement(entry.getUrl());
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
