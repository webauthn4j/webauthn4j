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

package com.webauthn4j.validator;


import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.CertPathTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.ecdaa.ECDAATrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.self.SelfAttestationTrustworthinessValidator;
import com.webauthn4j.validator.exception.ConstraintViolationException;
import com.webauthn4j.validator.exception.UserNotPresentException;
import com.webauthn4j.validator.exception.UserNotVerifiedException;
import org.junit.jupiter.api.Test;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

class WebAuthnRegistrationContextValidatorTest {

    private CertPathTrustworthinessValidator certPathTrustworthinessValidatorMock = mock(CertPathTrustworthinessValidator.class);
    private ECDAATrustworthinessValidator ecdaaTrustworthinessValidatorMock = mock(ECDAATrustworthinessValidator.class);
    private SelfAttestationTrustworthinessValidator selfAttestationTrustworthinessValidator = mock(SelfAttestationTrustworthinessValidator.class);


    @Test
    void constructor_test() {

        WebAuthnRegistrationContextValidator validator1 = new WebAuthnRegistrationContextValidator(
                Collections.emptyList(),
                certPathTrustworthinessValidatorMock,
                ecdaaTrustworthinessValidatorMock);

        WebAuthnRegistrationContextValidator validator2 = new WebAuthnRegistrationContextValidator(
                Collections.emptyList(),
                certPathTrustworthinessValidatorMock,
                ecdaaTrustworthinessValidatorMock);

        WebAuthnRegistrationContextValidator validator3 = new WebAuthnRegistrationContextValidator(
                Collections.emptyList(),
                certPathTrustworthinessValidatorMock,
                ecdaaTrustworthinessValidatorMock,
                selfAttestationTrustworthinessValidator);

        assertAll(
                () -> assertThat(validator1).hasFieldOrProperty("attestationValidator").isNotNull(),
                () -> assertThat(validator2).hasFieldOrProperty("attestationValidator").isNotNull(),
                () -> assertThat(validator3).hasFieldOrProperty("attestationValidator").isNotNull()
        );
    }

    @Test
    void validateAuthenticatorDataField_test() {
        AuthenticatorData authenticatorData = new AuthenticatorData(null, (byte) 0, 0);
        assertThrows(ConstraintViolationException.class,
                () -> WebAuthnRegistrationContextValidator.createNonStrictRegistrationContextValidator().validateAuthenticatorDataField(authenticatorData)
        );
    }

    @Test
    void validateUVUPFlags_not_required_test() {
        AuthenticatorData authenticatorData = new AuthenticatorData(null, (byte) 0, 0);
        WebAuthnRegistrationContextValidator.createNonStrictRegistrationContextValidator().validateUVUPFlags(authenticatorData, false, false);
    }

    @Test
    void validateUVUPFlags_required_test() {
        AuthenticatorData authenticatorData = new AuthenticatorData(null, (byte) (AuthenticatorData.BIT_UP | AuthenticatorData.BIT_UV), 0);
        WebAuthnRegistrationContextValidator.createNonStrictRegistrationContextValidator().validateUVUPFlags(authenticatorData, true, true);
    }

    @Test
    void validateUVUPFlags_UserNotVerifiedException_test() {
        AuthenticatorData authenticatorData = new AuthenticatorData(null, (byte) 0, 0);
        assertThrows(UserNotVerifiedException.class,
                () -> WebAuthnRegistrationContextValidator.createNonStrictRegistrationContextValidator().validateUVUPFlags(authenticatorData, true, false)
        );
    }

    @Test
    void validateUVUPFlags_UserNotPresentException_test() {
        AuthenticatorData authenticatorData = new AuthenticatorData(null, (byte) 0, 0);
        assertThrows(UserNotPresentException.class,
                () -> WebAuthnRegistrationContextValidator.createNonStrictRegistrationContextValidator().validateUVUPFlags(authenticatorData, false, true)
        );
    }
}