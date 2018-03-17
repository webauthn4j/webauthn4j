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

package net.sharplab.springframework.security.webauthn.context.validator;


import net.sharplab.springframework.security.webauthn.attestation.WebAuthnAttestationObject;
import net.sharplab.springframework.security.webauthn.attestation.authenticator.WebAuthnAuthenticatorData;
import net.sharplab.springframework.security.webauthn.attestation.statement.WebAuthnAttestationStatement;
import net.sharplab.springframework.security.webauthn.client.CollectedClientData;
import net.sharplab.springframework.security.webauthn.context.RelyingParty;
import net.sharplab.springframework.security.webauthn.context.WebAuthnRegistrationContext;
import net.sharplab.springframework.security.webauthn.context.validator.attestation.signature.AttestationStatementSignatureValidator;
import net.sharplab.springframework.security.webauthn.context.validator.attestation.signature.FIDOU2FAttestationStatementSignatureValidator;
import net.sharplab.springframework.security.webauthn.context.validator.attestation.signature.NoneAttestationStatementSignatureValidator;
import net.sharplab.springframework.security.webauthn.context.validator.attestation.signature.WebAuthnAttestationStatementSignatureValidator;
import net.sharplab.springframework.security.webauthn.context.validator.attestation.trustworthiness.AttestationStatementTrustworthinessValidator;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.SpringSecurityMessageSource;

import java.util.Arrays;
import java.util.List;

/**
 * Validates {@link WebAuthnRegistrationContext} instance
 */
public class WebAuthnRegistrationContextValidator {

    //~ Instance fields
    // ================================================================================================
    protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

    private List<AttestationStatementSignatureValidator> attestationStatementSignatureValidators;
    private AttestationStatementTrustworthinessValidator attestationStatementTrustworthinessValidator;

    private ChallengeValidator challengeValidator = new ChallengeValidator();
    private OriginValidator originValidator = new OriginValidator();
    private RpIdHashValidator rpIdHashValidator = new RpIdHashValidator();

    public WebAuthnRegistrationContextValidator(AttestationStatementTrustworthinessValidator attestationStatementTrustworthinessValidator){
        attestationStatementSignatureValidators = Arrays.asList(
                new FIDOU2FAttestationStatementSignatureValidator(),
                new WebAuthnAttestationStatementSignatureValidator(),
                new NoneAttestationStatementSignatureValidator()
        );
        this.attestationStatementTrustworthinessValidator = attestationStatementTrustworthinessValidator;
    }

    public void validate(WebAuthnRegistrationContext registrationContext){

        CollectedClientData collectedClientData = registrationContext.getCollectedClientData();
        WebAuthnAttestationObject attestationObject = registrationContext.getAttestationObject();
        WebAuthnAuthenticatorData authenticatorData = attestationObject.getAuthenticatorData();
        WebAuthnAttestationStatement attestationStatement = attestationObject.getAttestationStatement();
        RelyingParty relyingParty = registrationContext.getRelyingParty();

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
        validateAttestationStatementSignature(registrationContext);

        // If validation is successful, obtain a list of acceptable trust anchor (attestation root certificates
        // or ECDAA-Issuer public keys) for that attestation type and attestation statement format fmt,
        // from a trusted source or from policy. For example, the FIDO Metadata Service [FIDOMetadataService]
        // provides one way to obtain such information, using the AAGUID in the attestation data contained in authData.
        //
        // Assess the attestation trustworthiness using the outputs of the verification procedure in step 10
        attestationStatementTrustworthinessValidator.validate(attestationStatement);

        // If the attestation statement attStmt verified successfully and is found to be trustworthy,
        // then register the new credential with the account that was denoted in the options.user passed to create(),
        // by associating it with the credential ID and credential public key contained in authData’s attestation data,
        // as appropriate for the Relying Party's systems.

    }

    void validateAttestationStatementSignature(WebAuthnRegistrationContext registrationContext){
        for(AttestationStatementSignatureValidator attestationStatementSignatureValidator : attestationStatementSignatureValidators){
            if(attestationStatementSignatureValidator.supports(registrationContext.getAttestationObject().getFormat())){
                attestationStatementSignatureValidator.validate(registrationContext);
                return;
            }
        }

        throw new InternalAuthenticationServiceException(messages.getMessage(
                "WebAuthnRegistrationContextValidator.noAttestationStatementSignatureValidator",
                "No applicable AttestationStatementSignatureValidator is available"));
    }

}
