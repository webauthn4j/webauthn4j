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

package com.webauthn4j;

import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.*;
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
import com.webauthn4j.validator.attestation.trustworthiness.self.NullSelfAttestationTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.self.SelfAttestationTrustworthinessValidator;
import com.webauthn4j.validator.exception.ValidationException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class WebAuthnManager {

    // ~ Instance fields
    // ================================================================================================

    private final WebAuthnRegistrationManager webAuthnRegistrationManager;
    private final WebAuthnAuthenticationManager webAuthnAuthenticationManager;

    public WebAuthnManager(List<AttestationStatementValidator> attestationStatementValidators,
                           CertPathTrustworthinessValidator certPathTrustworthinessValidator,
                           SelfAttestationTrustworthinessValidator selfAttestationTrustworthinessValidator,
                           List<CustomRegistrationValidator> customRegistrationValidators,
                           List<CustomAuthenticationValidator> customAuthenticationValidators,
                           ObjectConverter objectConverter) {

        this.webAuthnRegistrationManager = new WebAuthnRegistrationManager(
                attestationStatementValidators,
                certPathTrustworthinessValidator,
                selfAttestationTrustworthinessValidator,
                customRegistrationValidators,
                objectConverter);
        this.webAuthnAuthenticationManager = new WebAuthnAuthenticationManager(
                customAuthenticationValidators,
                objectConverter);
    }

    public WebAuthnManager(List<AttestationStatementValidator> attestationStatementValidators,
                           CertPathTrustworthinessValidator certPathTrustworthinessValidator,
                           SelfAttestationTrustworthinessValidator selfAttestationTrustworthinessValidator,
                           List<CustomRegistrationValidator> customRegistrationValidators,
                           List<CustomAuthenticationValidator> customAuthenticationValidators) {
        this(
                attestationStatementValidators,
                certPathTrustworthinessValidator,
                selfAttestationTrustworthinessValidator,
                customRegistrationValidators,
                customAuthenticationValidators,
                new ObjectConverter()
        );
    }

    public WebAuthnManager(List<AttestationStatementValidator> attestationStatementValidators,
                           CertPathTrustworthinessValidator certPathTrustworthinessValidator,
                           SelfAttestationTrustworthinessValidator selfAttestationTrustworthinessValidator,
                           ObjectConverter objectConverter) {
        this(
                attestationStatementValidators,
                certPathTrustworthinessValidator,
                selfAttestationTrustworthinessValidator,
                new ArrayList<>(),
                new ArrayList<>(),
                objectConverter
        );
    }

    public WebAuthnManager(List<AttestationStatementValidator> attestationStatementValidators,
                           CertPathTrustworthinessValidator certPathTrustworthinessValidator,
                           SelfAttestationTrustworthinessValidator selfAttestationTrustworthinessValidator) {
        this(
                attestationStatementValidators,
                certPathTrustworthinessValidator,
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
                new NullSelfAttestationTrustworthinessValidator(),
                objectConverter
        );
    }


    @SuppressWarnings("squid:S1130")
    public RegistrationData parse(RegistrationRequest registrationRequest) throws DataConversionException {
        return this.webAuthnRegistrationManager.parse(registrationRequest);
    }

    @SuppressWarnings("squid:S1130")
    public RegistrationData validate(RegistrationRequest registrationRequest, RegistrationParameters registrationParameters) throws DataConversionException, ValidationException {
        return this.webAuthnRegistrationManager.validate(registrationRequest, registrationParameters);
    }

    @SuppressWarnings("squid:S1130")
    public RegistrationData validate(RegistrationData registrationData, RegistrationParameters registrationParameters) throws ValidationException {
        return this.webAuthnRegistrationManager.validate(registrationData, registrationParameters);
    }

    @SuppressWarnings("squid:S1130")
    public AuthenticationData parse(AuthenticationRequest authenticationRequest) throws DataConversionException {
        return this.webAuthnAuthenticationManager.parse(authenticationRequest);
    }

    @SuppressWarnings("squid:S1130")
    public AuthenticationData validate(AuthenticationRequest authenticationRequest, AuthenticationParameters authenticationParameters) throws DataConversionException, ValidationException {
        return this.webAuthnAuthenticationManager.validate(authenticationRequest, authenticationParameters);
    }

    @SuppressWarnings("squid:S1130")
    public AuthenticationData validate(AuthenticationData authenticationData, AuthenticationParameters authenticationParameters) throws ValidationException {
        return this.webAuthnAuthenticationManager.validate(authenticationData, authenticationParameters);
    }


    public RegistrationDataValidator getRegistrationDataValidator() {
        return this.webAuthnRegistrationManager.getRegistrationDataValidator();
    }

    public AuthenticationDataValidator getAuthenticationDataValidator() {
        return this.webAuthnAuthenticationManager.getAuthenticationDataValidator();
    }
}
