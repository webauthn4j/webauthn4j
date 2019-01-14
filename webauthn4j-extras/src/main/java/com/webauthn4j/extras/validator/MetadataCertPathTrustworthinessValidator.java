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

import com.webauthn4j.extras.fido.metadata.Metadata;
import com.webauthn4j.extras.fido.metadata.MetadataResolver;
import com.webauthn4j.response.attestation.authenticator.AAGUID;
import com.webauthn4j.response.attestation.statement.CertificateBaseAttestationStatement;
import com.webauthn4j.util.WIP;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.CertPathTrustworthinessValidatorBase;
import com.webauthn4j.validator.exception.CertificateException;

import java.security.cert.TrustAnchor;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * MetadataCertPathTrustworthinessValidator
 */
@WIP
public class MetadataCertPathTrustworthinessValidator extends CertPathTrustworthinessValidatorBase {

    private MetadataResolver metadataResolver;

    public MetadataCertPathTrustworthinessValidator(MetadataResolver metadataResolver) {
        this.metadataResolver = metadataResolver;
    }

    @Override
    public void validate(AAGUID aaguid, CertificateBaseAttestationStatement attestationStatement) {
        Metadata metadata = metadataResolver.resolve(aaguid);
        if (metadata == null) {
            throw new CertificateException("metadata not found");
        }
        metadata.getStatusReports().forEach(report -> {
            switch (report.getStatus()) {
                case FIDO_CERTIFIED:
                case UPDATE_AVAILABLE:
                case NOT_FIDO_CERTIFIED:
                    return;
                case ATTESTATION_KEY_COMPROMISE:
                case USER_VERIFICATION_BYPASS:
                case USER_KEY_REMOTE_COMPROMISE:
                case USER_KEY_PHYSICAL_COMPROMISE:
                case REVOKED:
                default:
                    throw new CertificateException(String.format("error response from metadata service: %s", report.getStatus()));
            }
        });
        super.validate(aaguid, attestationStatement);
    }

    @Override
    protected Set<TrustAnchor> resolveTrustAnchors(AAGUID aaguid) {
        return metadataResolver.resolve(aaguid).getMetadataStatement().getAttestationRootCertificates().stream()
                .map(certificate -> new TrustAnchor(certificate, null))
                .collect(Collectors.toSet());
    }


}
