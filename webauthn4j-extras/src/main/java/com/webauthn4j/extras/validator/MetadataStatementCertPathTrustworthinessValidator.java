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

package com.webauthn4j.extras.validator;

import com.webauthn4j.extras.fido.metadata.statement.AttestationType;
import com.webauthn4j.extras.fido.metadata.statement.MetadataStatement;
import com.webauthn4j.extras.fido.metadata.statement.MetadataStatementResolver;
import com.webauthn4j.response.attestation.authenticator.AAGUID;
import com.webauthn4j.response.attestation.statement.CertificateBaseAttestationStatement;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.CertPathTrustworthinessValidatorBase;
import com.webauthn4j.validator.exception.BadAttestationStatementException;

import java.security.cert.TrustAnchor;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class MetadataStatementCertPathTrustworthinessValidator extends CertPathTrustworthinessValidatorBase {

    private MetadataStatementResolver metadataStatementResolver;

    public MetadataStatementCertPathTrustworthinessValidator(MetadataStatementResolver metadataStatementResolver) {
        this.metadataStatementResolver = metadataStatementResolver;
    }

    public void validate(AAGUID aaguid, CertificateBaseAttestationStatement attestationStatement) {
        List<MetadataStatement> metadataStatements = metadataStatementResolver.resolve(aaguid);
        boolean isSurrogate = metadataStatements.stream().flatMap(item -> item.getAttestationTypes().stream()).allMatch(type -> type.equals(AttestationType.ATTESTATION_BASIC_SURROGATE));
        if (isSurrogate && attestationStatement.getX5c() != null) {
            throw new BadAttestationStatementException("Although aaguid is for surrogate attestation, x5c contains certificates");
        }
        super.validate(aaguid, attestationStatement);
    }

    @Override
    protected Set<TrustAnchor> resolveTrustAnchors(AAGUID aaguid) {
        return metadataStatementResolver.resolve(aaguid).stream()
                .flatMap(metadataStatement ->
                        metadataStatement.getAttestationRootCertificates().stream()
                                .map(certificate -> new TrustAnchor(certificate, null)))
                .collect(Collectors.toSet()
                );
    }
}
