/*
 * Copyright 2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webauthn4j.validator;

import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.data.attestation.statement.AttestationType;
import com.webauthn4j.data.attestation.statement.CertificateBaseAttestationStatement;
import com.webauthn4j.data.attestation.statement.FIDOU2FAttestationStatement;
import com.webauthn4j.validator.attestation.statement.AttestationStatementValidator;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.CertPathTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.self.SelfAttestationTrustworthinessValidator;
import com.webauthn4j.validator.exception.BadAaguidException;
import com.webauthn4j.validator.exception.BadAttestationStatementException;

import java.util.List;
import java.util.Objects;

/**
 * Validates the attestation
 */
class AttestationValidator {

    // ~ Instance fields
    // ================================================================================================

    private static final AAGUID U2F_AAGUID = AAGUID.ZERO;

    private final List<AttestationStatementValidator> attestationStatementValidators;

    private final CertPathTrustworthinessValidator certPathTrustworthinessValidator;
    private final SelfAttestationTrustworthinessValidator selfAttestationTrustworthinessValidator;

    // ~ Constructor
    // ========================================================================================================

    AttestationValidator(
            List<AttestationStatementValidator> attestationStatementValidators,
            CertPathTrustworthinessValidator certPathTrustworthinessValidator,
            SelfAttestationTrustworthinessValidator selfAttestationTrustworthinessValidator
    ) {
        this.attestationStatementValidators = attestationStatementValidators;

        this.certPathTrustworthinessValidator = certPathTrustworthinessValidator;
        this.selfAttestationTrustworthinessValidator = selfAttestationTrustworthinessValidator;
    }


    public void validate(RegistrationObject registrationObject) {

        AttestationObject attestationObject = registrationObject.getAttestationObject();

        //spec| Determine the attestation statement format by performing a USASCII case-sensitive match on fmt against the set
        //spec| of supported WebAuthn Attestation Statement Format Identifier values. The up-to-date list of registered
        //spec| WebAuthn Attestation Statement Format Identifier values is maintained in the in the IANA registry of the same
        //spec| name [WebAuthn-Registries].

        //spec| Verify that attStmt is a correct attestation statement, conveying a valid attestation signature, by using the
        //spec| attestation statement format fmt’s verification procedure given attStmt, authData and the hash of the
        //spec| serialized client data computed in step 7.

        //spec| Note: Each attestation statement format specifies its own verification procedure. See §8 Defined Attestation
        //spec| Statement Formats for the initially-defined formats, and  [WebAuthn-Registries] for the up-to-date list.
        AttestationType attestationType = validateAttestationStatement(registrationObject);

        validateAAGUID(attestationObject);

        //spec| If validation is successful, obtain a list of acceptable trust anchors (attestation root certificates or
        //spec| ECDAA-Issuer public keys) for that attestation type and attestation statement format fmt,
        //spec| from a trusted source or from policy.
        //spec| For example, the FIDO Metadata Service [FIDOMetadataService] provides one way to obtain such information,
        //spec| using the aaguid in the attestedCredentialData in authData.

        //spec| Assess the attestation trustworthiness using the outputs of the verification procedure in step 14, as follows:

        AttestationStatement attestationStatement = attestationObject.getAttestationStatement();
        switch (attestationType) {
            // If self attestation was used, check if self attestation is acceptable under Relying Party policy.
            case SELF:
                if (attestationStatement instanceof CertificateBaseAttestationStatement) {
                    CertificateBaseAttestationStatement certificateBaseAttestationStatement =
                            (CertificateBaseAttestationStatement) attestationStatement;
                    selfAttestationTrustworthinessValidator.validate(certificateBaseAttestationStatement);
                } else {
                    throw new IllegalStateException();
                }
                break;

            // Otherwise, use the X.509 certificates returned by the verification procedure to verify that
            // the attestation public key correctly chains up to an acceptable root certificate.
            case BASIC:
            case ATT_CA:
                if (attestationStatement instanceof CertificateBaseAttestationStatement) {
                    CertificateBaseAttestationStatement certificateBaseAttestationStatement =
                            (CertificateBaseAttestationStatement) attestationStatement;
                    AAGUID aaguid = attestationObject.getAuthenticatorData().getAttestedCredentialData().getAaguid();
                    certPathTrustworthinessValidator.validate(aaguid, certificateBaseAttestationStatement);
                } else {
                    throw new IllegalStateException();
                }
                break;
            case NONE:
                // nop
                break;
            default:
                throw new IllegalStateException();
        }

    }

    void validateAAGUID(AttestationObject attestationObject) {
        if (attestationObject.getFormat().equals(FIDOU2FAttestationStatement.FORMAT)) {
            AAGUID aaguid = attestationObject.getAuthenticatorData().getAttestedCredentialData().getAaguid();
            if (!Objects.equals(aaguid, U2F_AAGUID)) {
                throw new BadAaguidException("AAGUID is expected to be zero filled in U2F attestation, but it isn't.");
            }
        }
    }

    private AttestationType validateAttestationStatement(RegistrationObject registrationObject) {
        for (AttestationStatementValidator validator : attestationStatementValidators) {
            if (validator.supports(registrationObject)) {
                return validator.validate(registrationObject);
            }
        }

        throw new BadAttestationStatementException(String.format("AttestationValidator is not configured to handle the supplied AttestationStatement format '%s'.", registrationObject.getAttestationObject().getFormat()));
    }
}
