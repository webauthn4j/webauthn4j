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
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.validator.attestation.statement.AttestationStatementValidator;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.CertPathTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.self.SelfAttestationTrustworthinessValidator;
import com.webauthn4j.validator.exception.BadAaguidException;
import com.webauthn4j.validator.exception.BadAttestationStatementException;
import org.checkerframework.checker.nullness.qual.NonNull;

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
            @NonNull List<AttestationStatementValidator> attestationStatementValidators,
            @NonNull CertPathTrustworthinessValidator certPathTrustworthinessValidator,
            @NonNull SelfAttestationTrustworthinessValidator selfAttestationTrustworthinessValidator
    ) {
        AssertUtil.notNull(attestationStatementValidators, "attestationStatementValidators must not be null");
        AssertUtil.notNull(certPathTrustworthinessValidator, "certPathTrustworthinessValidator must not be null");
        AssertUtil.notNull(selfAttestationTrustworthinessValidator, "selfAttestationTrustworthinessValidator must not be null");

        this.attestationStatementValidators = attestationStatementValidators;
        this.certPathTrustworthinessValidator = certPathTrustworthinessValidator;
        this.selfAttestationTrustworthinessValidator = selfAttestationTrustworthinessValidator;
    }


    public void validate(@NonNull CoreRegistrationObject registrationObject) {
        AssertUtil.notNull(registrationObject, "registrationObject must not be null");

        AttestationObject attestationObject = registrationObject.getAttestationObject();

        //spec| Step21
        //spec| Determine the attestation statement format by performing a USASCII case-sensitive match on fmt against
        //spec| the set of supported WebAuthn Attestation Statement Format Identifier values.
        //spec| An up-to-date list of registered WebAuthn Attestation Statement Format Identifier values is maintained in
        //spec| the IANA "WebAuthn Attestation Statement Format Identifiers" registry [IANA-WebAuthn-Registries] established by [RFC8809].
        //spec| Step22
        //spec| Verify that attStmt is a correct attestation statement, conveying a valid attestation signature,
        //spec| by using the attestation statement format fmt’s verification procedure given attStmt, authData and hash.

        AttestationType attestationType = validateAttestationStatement(registrationObject);

        validateAAGUID(attestationObject);

        //spec| Step23
        //spec| If validation is successful, obtain a list of acceptable trust anchors (i.e. attestation root certificates)
        //spec| for that attestation type and attestation statement format fmt, from a trusted source or from policy.
        //spec| For example, the FIDO Metadata Service [FIDOMetadataService] provides one way to obtain such information,
        //spec| using the aaguid in the attestedCredentialData in authData.
        //spec| Step24
        //spec| Assess the attestation trustworthiness using the outputs of the verification procedure in step 19, as follows:
        //spec| If no attestation was provided, verify that None attestation is acceptable under Relying Party policy.
        //      (This is already done in validateAttestationStatement method)

        AttestationStatement attestationStatement = attestationObject.getAttestationStatement();
        switch (attestationType) {
            //spec| If self attestation was used, check if self attestation is acceptable under Relying Party policy.
            case SELF:
                if (attestationStatement instanceof CertificateBaseAttestationStatement) {
                    CertificateBaseAttestationStatement certificateBaseAttestationStatement =
                            (CertificateBaseAttestationStatement) attestationStatement;
                    selfAttestationTrustworthinessValidator.validate(certificateBaseAttestationStatement);
                }
                else {
                    throw new IllegalStateException();
                }
                break;

            //spec| Otherwise, use the X.509 certificates returned as the attestation trust path from the verification procedure
            //spec| to verify that the attestation public key either correctly chains up to an acceptable root certificate,
            //spec| or is itself an acceptable certificate (i.e., it and the root certificate obtained in Step 20 may be the same).
            case BASIC:
            case ATT_CA:
                if (attestationStatement instanceof CertificateBaseAttestationStatement) {
                    CertificateBaseAttestationStatement certificateBaseAttestationStatement =
                            (CertificateBaseAttestationStatement) attestationStatement;
                    //noinspection ConstantConditions as null check is already done in caller
                    AAGUID aaguid = attestationObject.getAuthenticatorData().getAttestedCredentialData().getAaguid();
                    certPathTrustworthinessValidator.validate(aaguid, certificateBaseAttestationStatement, registrationObject.getTimestamp());
                }
                else {
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

    void validateAAGUID(@NonNull AttestationObject attestationObject) {
        if (attestationObject.getFormat().equals(FIDOU2FAttestationStatement.FORMAT)) {
            //noinspection ConstantConditions as null check is already done in caller
            AAGUID aaguid = attestationObject.getAuthenticatorData().getAttestedCredentialData().getAaguid();
            if (!Objects.equals(aaguid, U2F_AAGUID)) {
                throw new BadAaguidException("AAGUID is expected to be zero filled in U2F attestation, but it isn't.");
            }
        }
    }

    private @NonNull AttestationType validateAttestationStatement(@NonNull CoreRegistrationObject registrationObject) {
        for (AttestationStatementValidator validator : attestationStatementValidators) {
            if (validator.supports(registrationObject)) {
                return validator.validate(registrationObject);
            }
        }

        throw new BadAttestationStatementException(String.format("AttestationValidator is not configured to handle the supplied AttestationStatement format '%s'.", registrationObject.getAttestationObject().getFormat()));
    }
}
