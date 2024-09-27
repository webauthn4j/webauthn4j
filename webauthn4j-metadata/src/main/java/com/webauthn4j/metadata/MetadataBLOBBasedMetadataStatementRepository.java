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

import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.metadata.data.MetadataBLOBPayloadEntry;
import com.webauthn4j.metadata.data.statement.MetadataStatement;
import com.webauthn4j.metadata.util.internal.MetadataBLOBUtil;
import com.webauthn4j.metadata.util.internal.MetadataStatementUtil;
import com.webauthn4j.util.HexUtil;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

public class MetadataBLOBBasedMetadataStatementRepository implements MetadataStatementRepository {

    private final List<MetadataBLOBProvider> metadataBLOBProviders;

    private boolean notFidoCertifiedAllowed = false;
    private boolean selfAssertionSubmittedAllowed = false;

    public MetadataBLOBBasedMetadataStatementRepository(MetadataBLOBProvider... metadataBLOBProviders) {
        this.metadataBLOBProviders = Arrays.asList(metadataBLOBProviders);
    }

    @Override
    public Set<MetadataStatement> find(AAGUID aaguid) {
        return metadataBLOBProviders.stream()
                .flatMap(provider -> provider.provide().getPayload().getEntries().stream())
                .filter(entry -> Objects.equals(entry.getAaguid(), aaguid))
                .filter(entry -> MetadataBLOBUtil.checkMetadataBLOBPayloadEntry(entry, notFidoCertifiedAllowed, selfAssertionSubmittedAllowed))
                .map(MetadataBLOBPayloadEntry::getMetadataStatement)
                .filter(MetadataStatementUtil::checkSurrogateMetadataStatementAttestationRootCertificate)
                .collect(Collectors.toSet());
    }

    @Override
    public Set<MetadataStatement> find(byte[] attestationCertificateKeyIdentifier) {
        return metadataBLOBProviders.stream()
                .flatMap(provider -> provider.provide().getPayload().getEntries().stream())
                .filter(entry -> matchAttestationCertificateKeyIdentifier(entry, attestationCertificateKeyIdentifier))
                .map(MetadataBLOBPayloadEntry::getMetadataStatement)
                .filter(MetadataStatementUtil::checkSurrogateMetadataStatementAttestationRootCertificate)
                .collect(Collectors.toSet());
    }

    public static boolean matchAttestationCertificateKeyIdentifier(MetadataBLOBPayloadEntry entry, byte[] attestationCertificateKeyIdentifier) {
        MetadataStatement metadataStatement = entry.getMetadataStatement();
        if(metadataStatement == null || metadataStatement.getAttestationCertificateKeyIdentifiers() == null){
            return false;
        }
        return metadataStatement.getAttestationCertificateKeyIdentifiers().stream().anyMatch(identifier -> Arrays.equals(HexUtil.decode(identifier), attestationCertificateKeyIdentifier));
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

}
