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

package com.webauthn4j.metadata.anchor;

import com.webauthn4j.anchor.TrustAnchorRepository;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.metadata.LocalFilesMetadataStatementsProvider;
import com.webauthn4j.metadata.MetadataStatementsProvider;
import com.webauthn4j.util.HexUtil;

import java.nio.file.Path;
import java.security.cert.TrustAnchor;
import java.util.Arrays;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

public class MetadataStatementsBasedTrustAnchorRepository implements TrustAnchorRepository {

    private final MetadataStatementsProvider metadataStatementsProvider;

    public MetadataStatementsBasedTrustAnchorRepository(MetadataStatementsProvider metadataStatementsProvider) {
        this.metadataStatementsProvider = metadataStatementsProvider;
    }

    public MetadataStatementsBasedTrustAnchorRepository(ObjectConverter objectConverter, Path... paths) {
        this(new LocalFilesMetadataStatementsProvider(objectConverter, paths));
    }

    @Override
    public Set<TrustAnchor> find(AAGUID aaguid) {
        return metadataStatementsProvider.provide().stream()
                .filter(metadataStatement -> Objects.equals(aaguid, metadataStatement.getAaguid()))
                .flatMap(metadataStatement -> metadataStatement.getAttestationRootCertificates().stream())
                .map(item -> new TrustAnchor(item, null))
                .collect(Collectors.toSet());
    }

    @Override
    public Set<TrustAnchor> find(byte[] attestationCertificateKeyIdentifier) {
        return metadataStatementsProvider.provide().stream()
                .filter(metadataStatement -> metadataStatement.getAttestationCertificateKeyIdentifiers() != null && metadataStatement.getAttestationCertificateKeyIdentifiers().stream().anyMatch(identifier -> Arrays.equals(HexUtil.decode(identifier), attestationCertificateKeyIdentifier)))
                .map(metadataStatement -> new TrustAnchor(metadataStatement.getAttestationRootCertificates().get(0), null))
                .collect(Collectors.toSet());
    }
}