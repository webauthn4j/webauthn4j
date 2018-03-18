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

package net.sharplab.springframework.security.webauthn.context.validator.attestation.trustworthiness.certpath;

import net.sharplab.springframework.security.fido.metadata.Metadata;
import net.sharplab.springframework.security.webauthn.anchor.FIDOMetadataServiceTrustAnchorService;
import net.sharplab.springframework.security.webauthn.attestation.statement.WebAuthnAttestationStatement;

/**
 * Created by ynojima on 2017/09/24.
 */
public class FIDOMetadataServiceCertPathTrustworthinessValidator implements CertPathTrustworthinessValidator {

    private FIDOMetadataServiceTrustAnchorService fidoMetadataServiceTrustAnchorService;

    public FIDOMetadataServiceCertPathTrustworthinessValidator(FIDOMetadataServiceTrustAnchorService fidoMetadataServiceTrustAnchorService) {
        this.fidoMetadataServiceTrustAnchorService = fidoMetadataServiceTrustAnchorService;
    }

    @Override
    public void validate(WebAuthnAttestationStatement attestationStatement) {

        Metadata metadata = fidoMetadataServiceTrustAnchorService.findMetadata(attestationStatement);
        if (metadata == null) {
            throw new RuntimeException(); //TODO
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
                    throw new RuntimeException(); //TODO
            }
        });
    }

}
