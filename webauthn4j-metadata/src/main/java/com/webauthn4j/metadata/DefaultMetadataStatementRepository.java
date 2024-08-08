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
import com.webauthn4j.metadata.data.statement.MetadataStatement;
import com.webauthn4j.metadata.util.internal.MetadataStatementUtil;
import com.webauthn4j.util.HexUtil;

import java.util.Arrays;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

public class DefaultMetadataStatementRepository implements MetadataStatementRepository{

    private final MetadataStatementsProvider metadataStatementsProvider;

    public DefaultMetadataStatementRepository(MetadataStatementsProvider metadataStatementsProvider) {
        this.metadataStatementsProvider = metadataStatementsProvider;
    }

    @Override
    public Set<MetadataStatement> find(AAGUID aaguid) {
        return metadataStatementsProvider.provide().stream()
                .filter(entry -> Objects.equals(entry.getAaguid(), aaguid))
                .filter(MetadataStatementUtil::checkSurrogateMetadataStatementAttestationRootCertificate)
                .collect(Collectors.toSet());
    }

    @Override
    public Set<MetadataStatement> find(byte[] attestationCertificateKeyIdentifier) {
        return metadataStatementsProvider.provide().stream()
                .filter(entry -> {
                    if(entry == null || entry.getAttestationCertificateKeyIdentifiers() == null){
                        return false;
                    }
                    return entry.getAttestationCertificateKeyIdentifiers().stream().anyMatch(identifier -> Arrays.equals(HexUtil.decode(identifier), attestationCertificateKeyIdentifier));
                })
                .filter(MetadataStatementUtil::checkSurrogateMetadataStatementAttestationRootCertificate)
                .collect(Collectors.toSet());
    }
}
