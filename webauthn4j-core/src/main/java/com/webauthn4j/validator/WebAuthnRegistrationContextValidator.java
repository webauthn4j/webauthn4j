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


import com.webauthn4j.rp.RelyingParty;
import com.webauthn4j.WebAuthnRegistrationContext;
import com.webauthn4j.attestation.AttestationObject;
import com.webauthn4j.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.attestation.statement.AttestationStatement;
import com.webauthn4j.attestation.statement.CertificateBaseAttestationStatement;
import com.webauthn4j.client.CollectedClientData;
import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.util.exception.NotImplementedException;
import com.webauthn4j.validator.attestation.AttestationStatementValidator;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.CertPathTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.ecdaa.ECDAATrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.self.SelfAttestationTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.self.SelfAttestationTrustworthinessValidatorImpl;
import com.webauthn4j.validator.exception.BadAttestationStatementException;
import com.webauthn4j.validator.exception.MaliciousDataException;

import java.util.List;
import java.util.Objects;

import static com.webauthn4j.client.CollectedClientData.TYPE_WEBAUTHN_CREATE;

/**
 * {@inheritDoc}
 */
public class WebAuthnRegistrationContextValidator {

    // ~ Instance fields
    // ================================================================================================

    private List<AttestationStatementValidator> attestationStatementValidators;
    private CertPathTrustworthinessValidator certPathTrustworthinessValidator;
    private ECDAATrustworthinessValidator ecdaaTrustworthinessValidator;
    private SelfAttestationTrustworthinessValidator selfAttestationTrustworthinessValidator;

    private ChallengeValidator challengeValidator = new ChallengeValidator();
    private OriginValidator originValidator = new OriginValidator();
    private RpIdHashValidator rpIdHashValidator = new RpIdHashValidator();

    private CollectedClientDataConverter collectedClientDataConverter = new CollectedClientDataConverter();
    private AttestationObjectConverter attestationObjectConverter = new AttestationObjectConverter();

    public WebAuthnRegistrationContextValidator(
            List<AttestationStatementValidator> attestationStatementValidators,
            CertPathTrustworthinessValidator certPathTrustworthinessValidator,
            ECDAATrustworthinessValidator ecdaaTrustworthinessValidator,
            SelfAttestationTrustworthinessValidator selfAttestationTrustworthinessValidator
    ) {
        AssertUtil.notNull(attestationStatementValidators, "attestationStatementValidators must not be null");
        AssertUtil.notNull(certPathTrustworthinessValidator, "certPathTrustworthinessValidator must not be null");
        AssertUtil.notNull(ecdaaTrustworthinessValidator, "ecdaaTrustworthinessValidator must not be null");
        AssertUtil.notNull(selfAttestationTrustworthinessValidator, "selfAttestationTrustworthinessValidator must not be null");

        this.attestationStatementValidators = attestationStatementValidators;
        this.certPathTrustworthinessValidator = certPathTrustworthinessValidator;
        this.ecdaaTrustworthinessValidator = ecdaaTrustworthinessValidator;
        this.selfAttestationTrustworthinessValidator = selfAttestationTrustworthinessValidator;
    }

    public WebAuthnRegistrationContextValidator(
            List<AttestationStatementValidator> attestationStatementValidators,
            CertPathTrustworthinessValidator certPathTrustworthinessValidator,
            ECDAATrustworthinessValidator ecdaaTrustworthinessValidator
    ) {
        this(
                attestationStatementValidators,
                certPathTrustworthinessValidator,
                ecdaaTrustworthinessValidator,
                new SelfAttestationTrustworthinessValidatorImpl()
        );
    }

    // ~ Methods
    // ========================================================================================================

    public void validate(WebAuthnRegistrationContext registrationContext) {
        byte[] clientDataBytes = registrationContext.getCollectedClientData();
        byte[] attestationObjectBytes = registrationContext.getAttestationObject();

        CollectedClientData collectedClientData = collectedClientDataConverter.convert(clientDataBytes);
        AttestationObject attestationObject = attestationObjectConverter.convert(attestationObjectBytes);


        RegistrationObject registrationObject = new RegistrationObject(
                collectedClientData,
                clientDataBytes,
                attestationObject,
                attestationObjectBytes,
                registrationContext.getRelyingParty()
        );

        AuthenticatorData authenticatorData = attestationObject.getAuthenticatorData();
        RelyingParty relyingParty = registrationContext.getRelyingParty();

        if (!Objects.equals(collectedClientData.getType(), TYPE_WEBAUTHN_CREATE)) {
            throw new MaliciousDataException("Bad client data type");
        }

        // Verify that the challenge in the collectedClientData matches the challenge that was sent to the authenticator
        // in the create() call.
        challengeValidator.validate(collectedClientData, relyingParty);

        // Verify that the origin in the collectedClientData matches the Relying Party's origin.
        originValidator.validate(collectedClientData, relyingParty);

        // Verify that the tokenBindingId in the collectedClientData matches the Token Binding ID for the TLS connection
        // over which the attestation was obtained.
        // TODO

        // Verify that the clientExtensions in the collectedClientData is a proper subset of the extensions requested by the RP
        // and that the authenticatorExtensions in the collectedClientData is also a proper subset of the extensions requested by the RP.
        // TODO

        // Verify that the RP ID hash in authData is indeed the SHA-256 hash of the RP ID expected by the RP.
        rpIdHashValidator.validate(authenticatorData.getRpIdHash(), relyingParty);

        // Verify that attStmt is a correct, validly-signed attestation statement, using the attestation statement
        // format fmt’s verification procedure given authenticator data authData and the hash of the serialized
        // client data computed in step 6.
        validateAttestationStatement(registrationObject);

        // If validation is successful, obtain a list of acceptable trust anchors (attestation root certificates or
        // ECDAA-Issuer public keys) for that attestation type and attestation statement format fmt,
        // from a trusted source or from policy.
        // For example, the FIDO Metadata Service [FIDOMetadataService] provides one way to obtain such information,
        // using the aaguid in the attestedCredentialData in authData.
        //
        // Assess the attestation trustworthiness using the outputs of the verification procedure in step 14, as follows:

        AttestationStatement attestationStatement = attestationObject.getAttestationStatement();
        switch (attestationStatement.getAttestationType()){
            // If self attestation was used, check if self attestation is acceptable under Relying Party policy.
            case Self:
                if(attestationStatement instanceof CertificateBaseAttestationStatement){
                    CertificateBaseAttestationStatement certificateBaseAttestationStatement =
                            (CertificateBaseAttestationStatement) attestationStatement;
                    selfAttestationTrustworthinessValidator.validate(certificateBaseAttestationStatement);
                }
                else {
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
            case Basic:
            case AttCA:
                if(attestationStatement instanceof CertificateBaseAttestationStatement){
                    CertificateBaseAttestationStatement certificateBaseAttestationStatement =
                            (CertificateBaseAttestationStatement) attestationStatement;
                    certPathTrustworthinessValidator.validate(certificateBaseAttestationStatement);
                }
                else {
                    throw new IllegalStateException();
                }
                break;
            case None:
                // nop
                break;
            default:
                throw new NotImplementedException();
        }

        // If the attestation statement attStmt verified successfully and is found to be trustworthy,
        // then register the new credential with the account that was denoted in the options.user passed to create(),
        // by associating it with the credential ID and credential public key contained in authData’s attestation data,
        // as appropriate for the Relying Party's systems.


    }

    private void validateAttestationStatement(RegistrationObject registrationObject) {
        for (AttestationStatementValidator validator : attestationStatementValidators) {
            if (validator.supports(registrationObject)) {
                validator.validate(registrationObject);
                return;
            }
        }

        throw new BadAttestationStatementException("Supplied AttestationStatement format is not configured.");
    }

}
