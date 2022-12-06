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

package com.webauthn4j;

import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.AuthenticationExtensionsClientOutputsConverter;
import com.webauthn4j.converter.AuthenticatorTransportConverter;
import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.RegistrationRequest;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.validator.CustomRegistrationValidator;
import com.webauthn4j.validator.RegistrationDataValidator;
import com.webauthn4j.validator.attestation.statement.AttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.androidkey.NullAndroidKeyAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.androidsafetynet.NullAndroidSafetyNetAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.apple.NullAppleAnonymousAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.none.NoneAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.packed.NullPackedAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.tpm.NullTPMAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.u2f.NullFIDOU2FAttestationStatementValidator;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.CertPathTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.NullCertPathTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.self.NullSelfAttestationTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.self.SelfAttestationTrustworthinessValidator;
import com.webauthn4j.validator.exception.ValidationException;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;

public class WebAuthnRegistrationManager {

    // ~ Instance fields
    // ================================================================================================
    private final Logger logger = LoggerFactory.getLogger(WebAuthnRegistrationManager.class);

    private final CollectedClientDataConverter collectedClientDataConverter;
    private final AttestationObjectConverter attestationObjectConverter;
    private final AuthenticatorTransportConverter authenticatorTransportConverter;
    private final AuthenticationExtensionsClientOutputsConverter authenticationExtensionsClientOutputsConverter;

    private final RegistrationDataValidator registrationDataValidator;

    public WebAuthnRegistrationManager(
            @NonNull List<AttestationStatementValidator> attestationStatementValidators,
            @NonNull CertPathTrustworthinessValidator certPathTrustworthinessValidator,
            @NonNull SelfAttestationTrustworthinessValidator selfAttestationTrustworthinessValidator,
            @NonNull List<CustomRegistrationValidator> customRegistrationValidators,
            @NonNull ObjectConverter objectConverter) {
        AssertUtil.notNull(attestationStatementValidators, "attestationStatementValidators must not be null");
        AssertUtil.notNull(certPathTrustworthinessValidator, "certPathTrustworthinessValidator must not be null");
        AssertUtil.notNull(selfAttestationTrustworthinessValidator, "selfAttestationTrustworthinessValidator must not be null");
        AssertUtil.notNull(customRegistrationValidators, "customRegistrationValidators must not be null");
        AssertUtil.notNull(objectConverter, "objectConverter must not be null");

        registrationDataValidator = new RegistrationDataValidator(
                attestationStatementValidators,
                certPathTrustworthinessValidator,
                selfAttestationTrustworthinessValidator,
                customRegistrationValidators,
                objectConverter);


        collectedClientDataConverter = new CollectedClientDataConverter(objectConverter);
        attestationObjectConverter = new AttestationObjectConverter(objectConverter);
        authenticatorTransportConverter = new AuthenticatorTransportConverter();
        authenticationExtensionsClientOutputsConverter = new AuthenticationExtensionsClientOutputsConverter(objectConverter);
    }

    public WebAuthnRegistrationManager(@NonNull List<AttestationStatementValidator> attestationStatementValidators,
                                       @NonNull CertPathTrustworthinessValidator certPathTrustworthinessValidator,
                                       @NonNull SelfAttestationTrustworthinessValidator selfAttestationTrustworthinessValidator,
                                       @NonNull List<CustomRegistrationValidator> customRegistrationValidators) {
        this(
                attestationStatementValidators,
                certPathTrustworthinessValidator,
                selfAttestationTrustworthinessValidator,
                customRegistrationValidators,
                new ObjectConverter()
        );
    }

    public WebAuthnRegistrationManager(@NonNull List<AttestationStatementValidator> attestationStatementValidators,
                                       @NonNull CertPathTrustworthinessValidator certPathTrustworthinessValidator,
                                       @NonNull SelfAttestationTrustworthinessValidator selfAttestationTrustworthinessValidator,
                                       @NonNull ObjectConverter objectConverter) {
        this(
                attestationStatementValidators,
                certPathTrustworthinessValidator,
                selfAttestationTrustworthinessValidator,
                Collections.emptyList(),
                objectConverter
        );
    }

    public WebAuthnRegistrationManager(@NonNull List<AttestationStatementValidator> attestationStatementValidators,
                                       @NonNull CertPathTrustworthinessValidator certPathTrustworthinessValidator,
                                       @NonNull SelfAttestationTrustworthinessValidator selfAttestationTrustworthinessValidator) {
        this(
                attestationStatementValidators,
                certPathTrustworthinessValidator,
                selfAttestationTrustworthinessValidator,
                Collections.emptyList()
        );
    }


    // ~ Factory methods
    // ========================================================================================================

    /**
     * Creates {@link WebAuthnRegistrationManager} with non strict configuration
     *
     * @return configured {@link WebAuthnRegistrationManager}
     */
    public static @NonNull WebAuthnRegistrationManager createNonStrictWebAuthnRegistrationManager() {
        ObjectConverter objectConverter = new ObjectConverter();
        return createNonStrictWebAuthnRegistrationManager(objectConverter);
    }

    /**
     * Creates {@link WebAuthnManager} with non strict configuration
     *
     * @param objectConverter ObjectConverter
     * @return configured {@link WebAuthnManager}
     */
    public static @NonNull WebAuthnRegistrationManager createNonStrictWebAuthnRegistrationManager(@NonNull ObjectConverter objectConverter) {
        return new WebAuthnRegistrationManager(
                Arrays.asList(
                        new NoneAttestationStatementValidator(),
                        new NullFIDOU2FAttestationStatementValidator(),
                        new NullPackedAttestationStatementValidator(),
                        new NullTPMAttestationStatementValidator(),
                        new NullAndroidKeyAttestationStatementValidator(),
                        new NullAndroidSafetyNetAttestationStatementValidator(),
                        new NullAppleAnonymousAttestationStatementValidator()
                ),
                new NullCertPathTrustworthinessValidator(),
                new NullSelfAttestationTrustworthinessValidator(),
                objectConverter
        );
    }

    @SuppressWarnings("squid:S1130")
    public @NonNull RegistrationData parse(@NonNull RegistrationRequest registrationRequest) throws DataConversionException {
        AssertUtil.notNull(registrationRequest, "registrationRequest must not be null");

        byte[] clientDataBytes = registrationRequest.getClientDataJSON();
        byte[] attestationObjectBytes = registrationRequest.getAttestationObject();

        logger.trace("Parse: {}", registrationRequest);

        CollectedClientData collectedClientData =
                clientDataBytes == null ? null : collectedClientDataConverter.convert(clientDataBytes);
        AttestationObject attestationObject =
                attestationObjectBytes == null ? null : attestationObjectConverter.convert(attestationObjectBytes);
        Set<AuthenticatorTransport> transports =
                registrationRequest.getTransports() == null ? null : authenticatorTransportConverter.convertSet(registrationRequest.getTransports());
        AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> clientExtensions =
                registrationRequest.getClientExtensionsJSON() == null ? null : authenticationExtensionsClientOutputsConverter.convert(registrationRequest.getClientExtensionsJSON());

        return new RegistrationData(
                attestationObject,
                attestationObjectBytes,
                collectedClientData,
                clientDataBytes,
                clientExtensions,
                transports
        );

    }

    @SuppressWarnings("squid:S1130")
    public @NonNull RegistrationData validate(@NonNull RegistrationRequest registrationRequest, @NonNull RegistrationParameters registrationParameters) throws DataConversionException, ValidationException {
        RegistrationData registrationData = parse(registrationRequest);
        return validate(registrationData, registrationParameters);
    }

    @SuppressWarnings("squid:S1130")
    public @NonNull RegistrationData validate(@NonNull RegistrationData registrationData, @NonNull RegistrationParameters registrationParameters) throws ValidationException {
        logger.trace("Validate: {}, {}", registrationData, registrationParameters);
        registrationDataValidator.validate(registrationData, registrationParameters);
        return registrationData;
    }

    public @NonNull RegistrationDataValidator getRegistrationDataValidator() {
        return registrationDataValidator;
    }

}
