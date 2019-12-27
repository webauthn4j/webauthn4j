/*
 * Copyright 2018 the original author or authors.
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

package com.webauthn4j;

import com.webauthn4j.converter.*;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.validator.CustomAuthenticationValidator;
import com.webauthn4j.validator.CustomRegistrationValidator;
import com.webauthn4j.validator.WebAuthnAuthenticationDataValidator;
import com.webauthn4j.validator.WebAuthnRegistrationDataValidator;
import com.webauthn4j.validator.attestation.statement.AttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.androidkey.NullAndroidKeyAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.androidsafetynet.NullAndroidSafetyNetAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.none.NoneAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.packed.NullPackedAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.tpm.NullTPMAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.u2f.NullFIDOU2FAttestationStatementValidator;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.CertPathTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.NullCertPathTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.ecdaa.ECDAATrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.ecdaa.NullECDAATrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.self.NullSelfAttestationTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.self.SelfAttestationTrustworthinessValidator;
import com.webauthn4j.validator.exception.ValidationException;

import java.util.*;

public class WebAuthnManager {

    // ~ Instance fields
    // ================================================================================================

    private final CollectedClientDataConverter collectedClientDataConverter;
    private final AttestationObjectConverter attestationObjectConverter;
    private final AuthenticatorDataConverter authenticatorDataConverter;
    private final AuthenticatorTransportConverter authenticatorTransportConverter;
    private final AuthenticationExtensionsClientOutputsConverter authenticationExtensionsClientOutputsConverter;

    private final WebAuthnRegistrationDataValidator webAuthnRegistrationDataValidator;
    private final WebAuthnAuthenticationDataValidator webAuthnAuthenticationDataValidator;

    public WebAuthnManager(List<AttestationStatementValidator> attestationStatementValidators,
                           CertPathTrustworthinessValidator certPathTrustworthinessValidator,
                           ECDAATrustworthinessValidator ecdaaTrustworthinessValidator,
                           SelfAttestationTrustworthinessValidator selfAttestationTrustworthinessValidator,
                           List<CustomRegistrationValidator> customRegistrationValidators,
                           List<CustomAuthenticationValidator> customAuthenticationValidators,
                           ObjectConverter objectConverter) {
        AssertUtil.notNull(attestationStatementValidators, "attestationStatementValidators must not be null");
        AssertUtil.notNull(certPathTrustworthinessValidator, "certPathTrustworthinessValidator must not be null");
        AssertUtil.notNull(ecdaaTrustworthinessValidator, "ecdaaTrustworthinessValidator must not be null");
        AssertUtil.notNull(selfAttestationTrustworthinessValidator, "selfAttestationTrustworthinessValidator must not be null");
        AssertUtil.notNull(customRegistrationValidators, "customRegistrationValidators must not be null");
        AssertUtil.notNull(customAuthenticationValidators, "customAuthenticationValidators must not be null");
        AssertUtil.notNull(objectConverter, "objectConverter must not be null");

        webAuthnRegistrationDataValidator = new WebAuthnRegistrationDataValidator(
                attestationStatementValidators,
                certPathTrustworthinessValidator,
                ecdaaTrustworthinessValidator,
                selfAttestationTrustworthinessValidator,
                customRegistrationValidators,
                objectConverter);

        webAuthnAuthenticationDataValidator = new WebAuthnAuthenticationDataValidator(customAuthenticationValidators);

        collectedClientDataConverter = new CollectedClientDataConverter(objectConverter);
        attestationObjectConverter = new AttestationObjectConverter(objectConverter);
        authenticatorDataConverter = new AuthenticatorDataConverter(objectConverter);
        authenticatorTransportConverter = new AuthenticatorTransportConverter();
        authenticationExtensionsClientOutputsConverter = new AuthenticationExtensionsClientOutputsConverter(objectConverter);

    }

    public WebAuthnManager(List<AttestationStatementValidator> attestationStatementValidators,
                           CertPathTrustworthinessValidator certPathTrustworthinessValidator,
                           ECDAATrustworthinessValidator ecdaaTrustworthinessValidator,
                           SelfAttestationTrustworthinessValidator selfAttestationTrustworthinessValidator,
                           List<CustomRegistrationValidator> customRegistrationValidators,
                           List<CustomAuthenticationValidator> customAuthenticationValidators) {
        this(
                attestationStatementValidators,
                certPathTrustworthinessValidator,
                ecdaaTrustworthinessValidator,
                selfAttestationTrustworthinessValidator,
                customRegistrationValidators,
                customAuthenticationValidators,
                new ObjectConverter()
        );
    }

    public WebAuthnManager(List<AttestationStatementValidator> attestationStatementValidators,
                           CertPathTrustworthinessValidator certPathTrustworthinessValidator,
                           ECDAATrustworthinessValidator ecdaaTrustworthinessValidator,
                           SelfAttestationTrustworthinessValidator selfAttestationTrustworthinessValidator,
                           ObjectConverter objectConverter) {
        this(
                attestationStatementValidators,
                certPathTrustworthinessValidator,
                ecdaaTrustworthinessValidator,
                selfAttestationTrustworthinessValidator,
                new ArrayList<>(),
                new ArrayList<>(),
                objectConverter
        );
    }

    public WebAuthnManager(List<AttestationStatementValidator> attestationStatementValidators,
                           CertPathTrustworthinessValidator certPathTrustworthinessValidator,
                           ECDAATrustworthinessValidator ecdaaTrustworthinessValidator,
                           SelfAttestationTrustworthinessValidator selfAttestationTrustworthinessValidator) {
        this(
                attestationStatementValidators,
                certPathTrustworthinessValidator,
                ecdaaTrustworthinessValidator,
                selfAttestationTrustworthinessValidator,
                new ArrayList<>(),
                new ArrayList<>()
        );
    }

    // ~ Factory methods
    // ========================================================================================================

    /**
     * Creates {@link WebAuthnManager} with non strict configuration
     *
     * @return configured {@link WebAuthnManager}
     */
    public static WebAuthnManager createNonStrictWebAuthnManager() {
        ObjectConverter objectConverter = new ObjectConverter();
        return createNonStrictWebAuthnManager(objectConverter);
    }

    /**
     * Creates {@link WebAuthnManager} with non strict configuration
     *
     * @return configured {@link WebAuthnManager}
     */
    public static WebAuthnManager createNonStrictWebAuthnManager(ObjectConverter objectConverter) {
        return new WebAuthnManager(
                Arrays.asList(
                        new NoneAttestationStatementValidator(),
                        new NullFIDOU2FAttestationStatementValidator(),
                        new NullPackedAttestationStatementValidator(),
                        new NullTPMAttestationStatementValidator(),
                        new NullAndroidKeyAttestationStatementValidator(),
                        new NullAndroidSafetyNetAttestationStatementValidator()
                ),
                new NullCertPathTrustworthinessValidator(),
                new NullECDAATrustworthinessValidator(),
                new NullSelfAttestationTrustworthinessValidator(),
                objectConverter
        );
    }


    public WebAuthnRegistrationData parse(WebAuthnRegistrationRequest webAuthnRegistrationRequest) throws DataConversionException {

        byte[] clientDataBytes = webAuthnRegistrationRequest.getClientDataJSON();
        byte[] attestationObjectBytes = webAuthnRegistrationRequest.getAttestationObject();

        CollectedClientData collectedClientData = collectedClientDataConverter.convert(clientDataBytes);
        AttestationObject attestationObject = attestationObjectConverter.convert(attestationObjectBytes);
        Set<AuthenticatorTransport> transports = authenticatorTransportConverter.convertSet(webAuthnRegistrationRequest.getTransports());
        AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> clientExtensions =
                authenticationExtensionsClientOutputsConverter.convert(webAuthnRegistrationRequest.getClientExtensionsJSON());

        return new WebAuthnRegistrationData(
                attestationObject,
                attestationObjectBytes,
                collectedClientData,
                clientDataBytes,
                clientExtensions,
                transports
        );

    }

    public WebAuthnRegistrationData validate(WebAuthnRegistrationRequest webAuthnRegistrationRequest, WebAuthnRegistrationParameters webAuthnRegistrationParameters) throws DataConversionException, ValidationException {
        WebAuthnRegistrationData webAuthnRegistrationData = parse(webAuthnRegistrationRequest);
        webAuthnRegistrationDataValidator.validate(webAuthnRegistrationData, webAuthnRegistrationParameters);
        return webAuthnRegistrationData;
    }

    public WebAuthnRegistrationData validate(WebAuthnRegistrationData webAuthnRegistrationData, WebAuthnRegistrationParameters webAuthnRegistrationParameters) throws ValidationException{
        webAuthnRegistrationDataValidator.validate(webAuthnRegistrationData, webAuthnRegistrationParameters);
        return webAuthnRegistrationData;
    }

    public WebAuthnAuthenticationData parse(WebAuthnAuthenticationRequest webAuthnAuthenticationRequest) throws DataConversionException{

        byte[] credentialId = webAuthnAuthenticationRequest.getCredentialId();
        byte[] signature = webAuthnAuthenticationRequest.getSignature();
        byte[] userHandle = webAuthnAuthenticationRequest.getUserHandle();
        byte[] clientDataBytes = webAuthnAuthenticationRequest.getClientDataJSON();
        CollectedClientData collectedClientData = collectedClientDataConverter.convert(clientDataBytes);
        byte[] authenticatorDataBytes = webAuthnAuthenticationRequest.getAuthenticatorData();
        AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData = authenticatorDataConverter.convert(authenticatorDataBytes);

        AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput> clientExtensions =
                authenticationExtensionsClientOutputsConverter.convert(webAuthnAuthenticationRequest.getClientExtensionsJSON());

        return new WebAuthnAuthenticationData(
                credentialId,
                userHandle,
                authenticatorData,
                authenticatorDataBytes,
                collectedClientData,
                clientDataBytes,
                clientExtensions,
                signature
        );

    }

    public WebAuthnAuthenticationData validate(WebAuthnAuthenticationRequest webAuthnAuthenticationRequest, WebAuthnAuthenticationParameters webAuthnAuthenticationParameters) throws DataConversionException, ValidationException {
        WebAuthnAuthenticationData webAuthnAuthenticationData = parse(webAuthnAuthenticationRequest);
        validate(webAuthnAuthenticationData, webAuthnAuthenticationParameters);
        return webAuthnAuthenticationData;
    }

    public WebAuthnAuthenticationData validate(WebAuthnAuthenticationData webAuthnAuthenticationData, WebAuthnAuthenticationParameters webAuthnAuthenticationParameters){
        webAuthnAuthenticationDataValidator.validate(webAuthnAuthenticationData, webAuthnAuthenticationParameters);
        return webAuthnAuthenticationData;
    }


    public WebAuthnRegistrationDataValidator getWebAuthnRegistrationDataValidator() {
        return webAuthnRegistrationDataValidator;
    }

    public WebAuthnAuthenticationDataValidator getWebAuthnAuthenticationDataValidator() {
        return webAuthnAuthenticationDataValidator;
    }
}
