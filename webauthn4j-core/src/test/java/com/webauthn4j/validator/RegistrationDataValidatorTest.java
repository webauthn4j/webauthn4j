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

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.validator.attestation.statement.androidkey.NullAndroidKeyAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.androidsafetynet.NullAndroidSafetyNetAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.none.NoneAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.packed.NullPackedAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.tpm.NullTPMAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.u2f.NullFIDOU2FAttestationStatementValidator;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.NullCertPathTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.self.NullSelfAttestationTrustworthinessValidator;
import com.webauthn4j.validator.exception.ConstraintViolationException;
import com.webauthn4j.validator.exception.UserNotPresentException;
import com.webauthn4j.validator.exception.UserNotVerifiedException;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

class RegistrationDataValidatorTest {

    private final RegistrationDataValidator target;

    public RegistrationDataValidatorTest() {
        ObjectConverter objectConverter = new ObjectConverter();

        target = new RegistrationDataValidator(Arrays.asList(
                new NoneAttestationStatementValidator(),
                new NullFIDOU2FAttestationStatementValidator(),
                new NullPackedAttestationStatementValidator(),
                new NullTPMAttestationStatementValidator(),
                new NullAndroidKeyAttestationStatementValidator(),
                new NullAndroidSafetyNetAttestationStatementValidator()
        ),
                new NullCertPathTrustworthinessValidator(),
                new NullSelfAttestationTrustworthinessValidator(),
                Collections.emptyList(),
                objectConverter);
    }

    @Test
    void validateAuthenticatorDataField_test() {
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput<?>> authenticatorData = new AuthenticatorData<>(null, (byte) 0, 0);
        assertThrows(ConstraintViolationException.class,
                () -> target.validateAuthenticatorDataField(authenticatorData)
        );
    }

    @Test
    void validateUVUPFlags_not_required_test() {
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput<?>> authenticatorData = new AuthenticatorData<>(null, (byte) 0, 0);
        target.validateUVUPFlags(authenticatorData, false, false);
    }

    @Test
    void validateUVUPFlags_required_test() {
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput<?>> authenticatorData = new AuthenticatorData<>(null, (byte) (AuthenticatorData.BIT_UP | AuthenticatorData.BIT_UV), 0);
        target.validateUVUPFlags(authenticatorData, true, true);
    }

    @Test
    void validateUVUPFlags_UserNotVerifiedException_test() {
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput<?>> authenticatorData = new AuthenticatorData<>(null, (byte) 0, 0);
        assertThrows(UserNotVerifiedException.class,
                () -> target.validateUVUPFlags(authenticatorData, true, false)
        );
    }

    @Test
    void validateUVUPFlags_UserNotPresentException_test() {
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput<?>> authenticatorData = new AuthenticatorData<>(null, (byte) 0, 0);
        assertThrows(UserNotPresentException.class,
                () -> target.validateUVUPFlags(authenticatorData, false, true)
        );
    }

    @Test
    void getCustomRegistrationValidators() {
        CustomRegistrationValidator customRegistrationValidator = mock(CustomRegistrationValidator.class);
        target.getCustomRegistrationValidators().add(customRegistrationValidator);
        assertThat(target.getCustomRegistrationValidators()).contains(customRegistrationValidator);
    }
}