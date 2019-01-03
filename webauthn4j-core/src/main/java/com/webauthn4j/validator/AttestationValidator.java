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

package com.webauthn4j.validator;

import com.webauthn4j.response.attestation.AttestationObject;
import com.webauthn4j.response.attestation.statement.AttestationStatement;
import com.webauthn4j.response.attestation.statement.AttestationType;
import com.webauthn4j.response.attestation.statement.CertificateBaseAttestationStatement;
import com.webauthn4j.response.attestation.statement.FIDOU2FAttestationStatement;
import com.webauthn4j.util.exception.NotImplementedException;
import com.webauthn4j.validator.attestation.AttestationStatementValidator;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.CertPathTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.ecdaa.ECDAATrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.self.SelfAttestationTrustworthinessValidator;
import com.webauthn4j.validator.exception.BadAaguidException;
import com.webauthn4j.validator.exception.BadAttestationStatementException;

import java.util.Arrays;
import java.util.List;

public class AttestationValidator {

    private static final byte[] U2F_AAGUID = new byte[16];

    private final List<AttestationStatementValidator> attestationStatementValidators;

    private final CertPathTrustworthinessValidator certPathTrustworthinessValidator;
    private final ECDAATrustworthinessValidator ecdaaTrustworthinessValidator;
    private final SelfAttestationTrustworthinessValidator selfAttestationTrustworthinessValidator;

    public AttestationValidator(
            List<AttestationStatementValidator> attestationStatementValidators,
            CertPathTrustworthinessValidator certPathTrustworthinessValidator,
            ECDAATrustworthinessValidator ecdaaTrustworthinessValidator,
            SelfAttestationTrustworthinessValidator selfAttestationTrustworthinessValidator
    ){
        this.attestationStatementValidators = attestationStatementValidators;

        this.certPathTrustworthinessValidator = certPathTrustworthinessValidator;
        this.ecdaaTrustworthinessValidator = ecdaaTrustworthinessValidator;
        this.selfAttestationTrustworthinessValidator = selfAttestationTrustworthinessValidator;
    }

    public void validate(RegistrationObject registrationObject){

        AttestationObject attestationObject = registrationObject.getAttestationObject();

        /// Determine the attestation statement format by performing a USASCII case-sensitive match on fmt against the set
        /// of supported WebAuthn Attestation Statement Format Identifier values. The up-to-date list of registered
        /// WebAuthn Attestation Statement Format Identifier values is maintained in the in the IANA registry of the same
        /// name [WebAuthn-Registries].

        /// Verify that attStmt is a correct attestation statement, conveying a valid attestation signature, by using the
        /// attestation statement format fmt’s verification procedure given attStmt, authData and the hash of the
        /// serialized client data computed in step 7.

        /// Note: Each attestation statement format specifies its own verification procedure. See §8 Defined Attestation
        /// Statement Formats for the initially-defined formats, and  [WebAuthn-Registries] for the up-to-date list.
        AttestationType attestationType = validateAttestationStatement(registrationObject);


        if(attestationObject.getFormat().equals(FIDOU2FAttestationStatement.FORMAT)){
            byte[] aaguid = attestationObject.getAuthenticatorData().getAttestedCredentialData().getAaguid();
            if(Arrays.equals(aaguid, U2F_AAGUID)){
                throw new BadAaguidException("AAGUID is not 0x00 though it is in U2F attestation.");
            }
        }


        /// If validation is successful, obtain a list of acceptable trust anchors (attestation root certificates or
        /// ECDAA-Issuer public keys) for that attestation type and attestation statement format fmt,
        /// from a trusted source or from policy.
        /// For example, the FIDO Metadata Service [FIDOMetadataService] provides one way to obtain such information,
        /// using the aaguid in the attestedCredentialData in authData.
        ///
        /// Assess the attestation trustworthiness using the outputs of the verification procedure in step 14, as follows:

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

            // If ECDAA was used, verify that the identifier of the ECDAA-Issuer public key used is included in the set of
            // acceptable trust anchors obtained in step 15.
            case ECDAA:
                ecdaaTrustworthinessValidator.validate(attestationStatement);
                break;
            // Otherwise, use the X.509 certificates returned by the verification procedure to verify that
            // the attestation public key correctly chains up to an acceptable root certificate.
            case BASIC:
            case ATT_CA:
                if (attestationStatement instanceof CertificateBaseAttestationStatement) {
                    CertificateBaseAttestationStatement certificateBaseAttestationStatement =
                            (CertificateBaseAttestationStatement) attestationStatement;
                    certPathTrustworthinessValidator.validate(certificateBaseAttestationStatement);
                } else {
                    throw new IllegalStateException();
                }
                break;
            case NONE:
                // nop
                break;
            default:
                throw new NotImplementedException();
        }

    }

    private AttestationType validateAttestationStatement(RegistrationObject registrationObject) {
        for (AttestationStatementValidator validator : attestationStatementValidators) {
            if (validator.supports(registrationObject)) {
                return validator.validate(registrationObject);
            }
        }

        throw new BadAttestationStatementException("Supplied AttestationStatement format is not configured.");
    }
}
