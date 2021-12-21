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

package com.webauthn4j.metadata.validator.attestation.trustworthiness.certpath;

import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.metadata.MetadataStatementsProvider;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.CertPathTrustworthinessValidatorBase;
import org.checkerframework.checker.nullness.qual.NonNull;

import java.security.cert.TrustAnchor;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

public class MetadataStatementsBasedCertPathTrustworthinessValidator extends CertPathTrustworthinessValidatorBase {

    private final MetadataStatementsProvider metadataStatementsProvider;

    public MetadataStatementsBasedCertPathTrustworthinessValidator(MetadataStatementsProvider metadataStatementsProvider){
        this.metadataStatementsProvider = metadataStatementsProvider;
    }

    @Override
    protected @NonNull Set<TrustAnchor> resolveTrustAnchors(@NonNull AAGUID aaguid) {
        return metadataStatementsProvider.provide().stream()
                .filter(item -> Objects.equals(aaguid, item.getAaguid()))
                .flatMap(item -> item.getAttestationRootCertificates().stream())
                .map(item -> new TrustAnchor(item, null))
                .collect(Collectors.toSet());
    }
}
