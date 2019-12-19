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

import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.validator.exception.ConstraintViolationException;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class WebAuthnAuthenticationContextValidatorTest {

    @Test
    void getter_setter_test() {
        WebAuthnAuthenticationContextValidator target = new WebAuthnAuthenticationContextValidator();

        MaliciousCounterValueHandler maliciousCounterValueHandler = new DefaultMaliciousCounterValueHandler();
        target.setMaliciousCounterValueHandler(maliciousCounterValueHandler);
        assertThat(target.getMaliciousCounterValueHandler()).isEqualTo(maliciousCounterValueHandler);

    }

    @Test
    void validateAuthenticatorData() {
        WebAuthnAuthenticationContextValidator target = new WebAuthnAuthenticationContextValidator();
        AuthenticatorData authenticatorData = new AuthenticatorData(new byte[32], AuthenticatorData.BIT_UP, 0);
        target.validateAuthenticatorData(authenticatorData);
    }

    @Test
    void validateAuthenticatorData_with_invalid_data() {
        WebAuthnAuthenticationContextValidator target = new WebAuthnAuthenticationContextValidator();
        AuthenticatorData authenticatorData = new AuthenticatorData(new byte[32], AuthenticatorData.BIT_AT, 0, new AttestedCredentialData());
        assertThrows(ConstraintViolationException.class,
                () -> target.validateAuthenticatorData(authenticatorData)
        );
    }
}
