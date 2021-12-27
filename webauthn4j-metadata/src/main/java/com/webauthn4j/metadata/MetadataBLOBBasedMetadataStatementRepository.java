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

package com.webauthn4j.metadata;

import com.webauthn4j.data.AuthenticatorAttestationType;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.metadata.data.MetadataBLOBPayloadEntry;
import com.webauthn4j.metadata.data.statement.MetadataStatement;
import com.webauthn4j.metadata.data.toc.StatusReport;
import com.webauthn4j.util.HexUtil;
import org.checkerframework.checker.nullness.qual.NonNull;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

public class MetadataBLOBBasedMetadataStatementRepository implements MetadataStatementRepository {

    private final List<MetadataBLOBProvider> metadataBLOBProviders;

    private boolean notFidoCertifiedAllowed = false;
    private boolean selfAssertionSubmittedAllowed = false;

    public MetadataBLOBBasedMetadataStatementRepository(List<MetadataBLOBProvider> metadataBLOBProviders) {
        this.metadataBLOBProviders = metadataBLOBProviders;
    }

    @Override
    public Set<MetadataStatement> find(AAGUID aaguid) {
        return metadataBLOBProviders.stream()
                .flatMap(provider -> provider.provide().getPayload().getEntries().stream())
                .filter(entry -> Objects.equals(entry.getAaguid(), aaguid))
                .filter(this::checkMetadataBLOBPayloadEntry)
                .map(MetadataBLOBPayloadEntry::getMetadataStatement)
                .filter(this::checkSurrogateMetadataStatementAttestationRootCertificate)
                .collect(Collectors.toSet());
    }

    @Override
    public Set<MetadataStatement> find(byte[] attestationCertificateKeyIdentifier) {
        return metadataBLOBProviders.stream()
                .flatMap(provider -> provider.provide().getPayload().getEntries().stream())
                .filter(entry -> {
                    MetadataStatement metadataStatement = entry.getMetadataStatement();
                    if(metadataStatement == null || metadataStatement.getAttestationCertificateKeyIdentifiers() == null){
                        return false;
                    }
                    return metadataStatement.getAttestationCertificateKeyIdentifiers().stream().anyMatch(identifier -> Arrays.equals(HexUtil.decode(identifier), attestationCertificateKeyIdentifier));
                })
                .map(MetadataBLOBPayloadEntry::getMetadataStatement)
                .filter(this::checkSurrogateMetadataStatementAttestationRootCertificate)
                .collect(Collectors.toSet());
    }


    public boolean isNotFidoCertifiedAllowed() {
        return notFidoCertifiedAllowed;
    }

    public void setNotFidoCertifiedAllowed(boolean notFidoCertifiedAllowed) {
        this.notFidoCertifiedAllowed = notFidoCertifiedAllowed;
    }

    public boolean isSelfAssertionSubmittedAllowed() {
        return selfAssertionSubmittedAllowed;
    }

    public void setSelfAssertionSubmittedAllowed(boolean selfAssertionSubmittedAllowed) {
        this.selfAssertionSubmittedAllowed = selfAssertionSubmittedAllowed;
    }

    private boolean checkMetadataBLOBPayloadEntry(@NonNull MetadataBLOBPayloadEntry metadataBLOBPayloadEntry) {
        List<StatusReport> statusReports = metadataBLOBPayloadEntry.getStatusReports();
        for (StatusReport report : statusReports) {
            switch (report.getStatus()) {
                //Info statuses
                case UPDATE_AVAILABLE:
                    // UPDATE_AVAILABLE itself doesn't mean security issue. If security related update is available,
                    // corresponding status report is expected to be added to the report list.
                    break;

                //Certification Related statuses
                case FIDO_CERTIFIED:
                case FIDO_CERTIFIED_L1:
                case FIDO_CERTIFIED_L1_PLUS:
                case FIDO_CERTIFIED_L2:
                case FIDO_CERTIFIED_L2_PLUS:
                case FIDO_CERTIFIED_L3:
                case FIDO_CERTIFIED_L3_PLUS:
                    break;
                case NOT_FIDO_CERTIFIED:
                    if (notFidoCertifiedAllowed) {
                        break;
                    }
                    else {
                        return false;
                    }
                case SELF_ASSERTION_SUBMITTED:
                    if (selfAssertionSubmittedAllowed) {
                        break;
                    }
                    else {
                        return false;
                    }

                    // Security Notification statuses
                case ATTESTATION_KEY_COMPROMISE:
                case USER_VERIFICATION_BYPASS:
                case USER_KEY_REMOTE_COMPROMISE:
                case USER_KEY_PHYSICAL_COMPROMISE:
                case REVOKED:
                default:
                    return false;
            }
        }
        return true;
    }

    private boolean checkSurrogateMetadataStatementAttestationRootCertificate(MetadataStatement metadataStatement) {
        boolean isSurrogate = metadataStatement != null && metadataStatement.getAttestationTypes().stream().allMatch(type -> type.equals(AuthenticatorAttestationType.BASIC_SURROGATE));

        if (isSurrogate) {
            return metadataStatement.getAttestationRootCertificates().isEmpty();
        }
        return true;
    }
}
