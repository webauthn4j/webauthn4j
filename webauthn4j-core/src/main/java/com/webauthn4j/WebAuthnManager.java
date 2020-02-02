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
import com.webauthn4j.validator.AuthenticationDataValidator;
import com.webauthn4j.validator.CustomAuthenticationValidator;
import com.webauthn4j.validator.CustomRegistrationValidator;
import com.webauthn4j.validator.RegistrationDataValidator;
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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

public class WebAuthnManager {

    // ~ Instance fields
    // ================================================================================================

    private final CollectedClientDataConverter collectedClientDataConverter;
    private final AttestationObjectConverter attestationObjectConverter;
    private final AuthenticatorDataConverter authenticatorDataConverter;
    private final AuthenticatorTransportConverter authenticatorTransportConverter;
    private final AuthenticationExtensionsClientOutputsConverter authenticationExtensionsClientOutputsConverter;

    private final RegistrationDataValidator registrationDataValidator;
    private final AuthenticationDataValidator authenticationDataValidator;

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

        registrationDataValidator = new RegistrationDataValidator(
                attestationStatementValidators,
                certPathTrustworthinessValidator,
                ecdaaTrustworthinessValidator,
                selfAttestationTrustworthinessValidator,
                customRegistrationValidators,
                objectConverter);

        authenticationDataValidator = new AuthenticationDataValidator(customAuthenticationValidators);

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
     * @param objectConverter ObjectConverter
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


    public RegistrationData parse(RegistrationRequest registrationRequest) throws DataConversionException {

        byte[] clientDataBytes = registrationRequest.getClientDataJSON();
        byte[] attestationObjectBytes = registrationRequest.getAttestationObject();

        CollectedClientData collectedClientData = collectedClientDataConverter.convert(clientDataBytes);
        AttestationObject attestationObject = attestationObjectConverter.convert(attestationObjectBytes);
        Set<AuthenticatorTransport> transports = authenticatorTransportConverter.convertSet(registrationRequest.getTransports());
        AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> clientExtensions =
                authenticationExtensionsClientOutputsConverter.convert(registrationRequest.getClientExtensionsJSON());

        return new RegistrationData(
                attestationObject,
                attestationObjectBytes,
                collectedClientData,
                clientDataBytes,
                clientExtensions,
                transports
        );

    }

    public RegistrationData validate(RegistrationRequest registrationRequest, RegistrationParameters registrationParameters) throws DataConversionException, ValidationException {
        RegistrationData registrationData = parse(registrationRequest);
        registrationDataValidator.validate(registrationData, registrationParameters);
        return registrationData;
    }

    public RegistrationData validate(RegistrationData registrationData, RegistrationParameters registrationParameters) throws ValidationException {
        registrationDataValidator.validate(registrationData, registrationParameters);
        return registrationData;
    }

    public AuthenticationData parse(AuthenticationRequest authenticationRequest) throws DataConversionException {

        byte[] credentialId = authenticationRequest.getCredentialId();
        byte[] signature = authenticationRequest.getSignature();
        byte[] userHandle = authenticationRequest.getUserHandle();
        byte[] clientDataBytes = authenticationRequest.getClientDataJSON();
        CollectedClientData collectedClientData = collectedClientDataConverter.convert(clientDataBytes);
        byte[] authenticatorDataBytes = authenticationRequest.getAuthenticatorData();
        AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData = authenticatorDataConverter.convert(authenticatorDataBytes);

        AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput> clientExtensions =
                authenticationExtensionsClientOutputsConverter.convert(authenticationRequest.getClientExtensionsJSON());

        return new AuthenticationData(
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

    public AuthenticationData validate(AuthenticationRequest authenticationRequest, AuthenticationParameters authenticationParameters) throws DataConversionException, ValidationException {
        AuthenticationData authenticationData = parse(authenticationRequest);
        validate(authenticationData, authenticationParameters);
        return authenticationData;
    }

    public AuthenticationData validate(AuthenticationData authenticationData, AuthenticationParameters authenticationParameters) {
        authenticationDataValidator.validate(authenticationData, authenticationParameters);
        return authenticationData;
    }


    public RegistrationDataValidator getRegistrationDataValidator() {
        return registrationDataValidator;
    }

    public AuthenticationDataValidator getAuthenticationDataValidator() {
        return authenticationDataValidator;
    }
}
