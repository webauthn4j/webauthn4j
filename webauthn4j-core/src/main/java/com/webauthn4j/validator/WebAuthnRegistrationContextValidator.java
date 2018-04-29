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


import com.webauthn4j.attestation.AttestationObject;
import com.webauthn4j.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.client.CollectedClientData;
import com.webauthn4j.RelyingParty;
import com.webauthn4j.WebAuthnRegistrationContext;
import com.webauthn4j.validator.attestation.AttestationStatementValidator;
import com.webauthn4j.validator.exception.MaliciousDataException;
import com.webauthn4j.validator.exception.UnsupportedAttestationStatementException;
import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.converter.AttestationObjectConverter;

import java.util.List;
import java.util.Objects;

import static com.webauthn4j.client.CollectedClientData.TYPE_WEBAUTHN_CREATE;

/**
 * Validates {@link WebAuthnRegistrationContext} instance
 */
public class WebAuthnRegistrationContextValidator {

    //~ Instance fields
    // ================================================================================================

    List<AttestationStatementValidator> attestationStatementValidators;

    private ChallengeValidator challengeValidator = new ChallengeValidator();
    private OriginValidator originValidator = new OriginValidator();
    private RpIdHashValidator rpIdHashValidator = new RpIdHashValidator();
    private CollectedClientDataConverter collectedClientDataConverter = new CollectedClientDataConverter();
    private AttestationObjectConverter attestationObjectConverter = new AttestationObjectConverter();

    public WebAuthnRegistrationContextValidator(List<AttestationStatementValidator> attestationStatementValidators) {
        this.attestationStatementValidators = attestationStatementValidators;
    }

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

        // If validation is successful, obtain a list of acceptable trust anchor (attestation root certificates
        // or ECDAA-Issuer public keys) for that attestation type and attestation statement format fmt,
        // from a trusted source or from policy. For example, the FIDO Metadata Service [FIDOMetadataService]
        // provides one way to obtain such information, using the AAGUID in the attestation data contained in authData.
        //
        // Assess the attestation trustworthiness using the outputs of the verification procedure in step 10
        validateAttestationStatement(registrationObject);

        // If the attestation statement attStmt verified successfully and is found to be trustworthy,
        // then register the new credential with the account that was denoted in the options.user passed to create(),
        // by associating it with the credential ID and credential public key contained in authData’s attestation data,
        // as appropriate for the Relying Party's systems.

    }

    void validateAttestationStatement(RegistrationObject registrationObject) {
        for (AttestationStatementValidator validator : attestationStatementValidators) {
            if (validator.supports(registrationObject)) {
                validator.validate(registrationObject);
                return;
            }
        }

        throw new UnsupportedAttestationStatementException("Supplied AttestationStatement format is not supported.");
    }

}
