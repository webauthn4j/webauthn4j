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

import com.webauthn4j.data.WebAuthnAuthenticationContext;
import com.webauthn4j.data.WebAuthnRegistrationContext;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.client.*;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.test.TestAttestationStatementUtil;
import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.validator.exception.ConstraintViolationException;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertThrows;

class BeanAssertUtilTest {

    @Test
    void validate_WebAuthnAuthenticationContext_test() {
        WebAuthnAuthenticationContext authenticationContext = new WebAuthnAuthenticationContext(
                new byte[32],
                new byte[512],
                new byte[512],
                new byte[32],
                TestDataUtil.createServerProperty(),
                true
        );
        BeanAssertUtil.validate(authenticationContext);
    }

    @Test
    void validate_WebAuthnAuthenticationContext_with_null_test() {
        assertThrows(ConstraintViolationException.class,
                () -> BeanAssertUtil.validate((WebAuthnAuthenticationContext) null)
        );
    }

    @Test
    void validate_WebAuthnAuthenticationContext_with_credentialId_null_test() {
        WebAuthnAuthenticationContext authenticationContext = new WebAuthnAuthenticationContext(
                null,
                new byte[512],
                new byte[512],
                new byte[32],
                TestDataUtil.createServerProperty(),
                true
        );
        assertThrows(ConstraintViolationException.class,
                () -> BeanAssertUtil.validate(authenticationContext)
        );
    }

    @Test
    void validate_WebAuthnAuthenticationContext_with_clientDataJSON_null_test() {
        WebAuthnAuthenticationContext authenticationContext = new WebAuthnAuthenticationContext(
                new byte[32],
                null,
                new byte[512],
                new byte[32],
                TestDataUtil.createServerProperty(),
                true
        );
        assertThrows(ConstraintViolationException.class,
                () -> BeanAssertUtil.validate(authenticationContext)
        );
    }

    @Test
    void validate_WebAuthnAuthenticationContext_with_authenticatorData_null_test() {
        WebAuthnAuthenticationContext authenticationContext = new WebAuthnAuthenticationContext(
                new byte[32],
                new byte[512],
                null,
                new byte[32],
                TestDataUtil.createServerProperty(),
                true
        );
        assertThrows(ConstraintViolationException.class,
                () -> BeanAssertUtil.validate(authenticationContext)
        );
    }

    @Test
    void validate_WebAuthnAuthenticationContext_with_signature_null_test() {
        WebAuthnAuthenticationContext authenticationContext = new WebAuthnAuthenticationContext(
                new byte[32],
                new byte[512],
                new byte[512],
                null,
                TestDataUtil.createServerProperty(),
                true
        );
        assertThrows(ConstraintViolationException.class,
                () -> BeanAssertUtil.validate(authenticationContext)
        );
    }

    @Test
    void validate_WebAuthnAuthenticationContext_with_serverProperty_null_test() {
        WebAuthnAuthenticationContext authenticationContext = new WebAuthnAuthenticationContext(
                new byte[32],
                new byte[512],
                new byte[512],
                new byte[32],
                null,
                true
        );
        assertThrows(ConstraintViolationException.class,
                () -> BeanAssertUtil.validate(authenticationContext)
        );
    }

    @Test
    void validate_WebAuthnRegistrationContext_test() {
        Set<String> transports = Collections.emptySet();
        WebAuthnRegistrationContext registrationContext = new WebAuthnRegistrationContext(
                new byte[512],
                new byte[512],
                transports,
                TestDataUtil.createServerProperty(),
                true
        );
        BeanAssertUtil.validate(registrationContext);
    }

    @Test
    void validate_WebAuthnRegistrationContext_with_null_test() {
        WebAuthnRegistrationContext nullValue = null;
        assertThrows(ConstraintViolationException.class,
                () -> BeanAssertUtil.validate(nullValue)
        );
    }

    @Test
    void validate_WebAuthnRegistrationContext_with_clientDataJSON_null_test() {
        Set<String> transports = Collections.emptySet();
        WebAuthnRegistrationContext registrationContext = new WebAuthnRegistrationContext(
                null,
                new byte[512],
                transports,
                TestDataUtil.createServerProperty(),
                true
        );
        assertThrows(ConstraintViolationException.class,
                () -> BeanAssertUtil.validate(registrationContext)
        );
    }

    @Test
    void validate_WebAuthnRegistrationContext_with_attestationObject_null_test() {
        Set<String> transports = Collections.emptySet();

        WebAuthnRegistrationContext registrationContext = new WebAuthnRegistrationContext(
                new byte[512],
                null,
                transports,
                TestDataUtil.createServerProperty(),
                true
        );
        assertThrows(ConstraintViolationException.class,
                () -> BeanAssertUtil.validate(registrationContext)
        );
    }

    @Test
    void validate_WebAuthnRegistrationContext_with_serverProperty_null_test() {
        Set<String> transports = Collections.emptySet();
        WebAuthnRegistrationContext registrationContext = new WebAuthnRegistrationContext(
                new byte[512],
                new byte[512],
                transports,
                null,
                true
        );
        assertThrows(ConstraintViolationException.class,
                () -> BeanAssertUtil.validate(registrationContext)
        );
    }

    @Test
    void validate_clientData_test() {
        CollectedClientData collectedClientData = new CollectedClientData(
                ClientDataType.GET,
                new DefaultChallenge(),
                new Origin("https://example.com"),
                new TokenBinding(TokenBindingStatus.PRESENT, new byte[32])
        );

        BeanAssertUtil.validate(collectedClientData);
    }

    @Test
    void validate_clientData_with_null_test() {
        assertThrows(ConstraintViolationException.class,
                () -> BeanAssertUtil.validate((CollectedClientData) null)
        );
    }

    @Test
    void validate_clientData_with_clientDataType_null_test() {
        CollectedClientData collectedClientData = new CollectedClientData(
                null,
                new DefaultChallenge(),
                new Origin("https://example.com"),
                new TokenBinding(TokenBindingStatus.PRESENT, new byte[32])
        );

        assertThrows(ConstraintViolationException.class,
                () -> BeanAssertUtil.validate(collectedClientData)
        );
    }

    @Test
    void validate_clientData_with_challenge_null_test() {
        CollectedClientData collectedClientData = new CollectedClientData(
                ClientDataType.GET,
                null,
                new Origin("https://example.com"),
                new TokenBinding(TokenBindingStatus.PRESENT, new byte[32])
        );

        assertThrows(ConstraintViolationException.class,
                () -> BeanAssertUtil.validate(collectedClientData)
        );
    }

    @Test
    void validate_clientData_with_origin_null_test() {
        CollectedClientData collectedClientData = new CollectedClientData(
                ClientDataType.GET,
                new DefaultChallenge(),
                null,
                new TokenBinding(TokenBindingStatus.PRESENT, new byte[32])
        );

        assertThrows(ConstraintViolationException.class,
                () -> BeanAssertUtil.validate(collectedClientData)
        );
    }

    @Test
    void validate_clientData_with_tokenBinding_null_test() {
        CollectedClientData collectedClientData = new CollectedClientData(
                ClientDataType.GET,
                new DefaultChallenge(),
                new Origin("https://example.com"),
                null
        );

        BeanAssertUtil.validate(collectedClientData);
    }

    @Test
    void validate_tokenBinding_test() {
        TokenBinding tokenBinding = new TokenBinding(TokenBindingStatus.PRESENT, new byte[32]);

        BeanAssertUtil.validate(tokenBinding);
    }

    @Test
    void validate_tokenBinding_with_not_supported_status_test() {
        TokenBinding tokenBinding = new TokenBinding(TokenBindingStatus.NOT_SUPPORTED, (String) null);

        BeanAssertUtil.validate(tokenBinding);
    }

    @Test
    void validate_tokenBinding_with_supported_status_test() {
        TokenBinding tokenBinding = new TokenBinding(TokenBindingStatus.SUPPORTED, (String) null);

        BeanAssertUtil.validate(tokenBinding);
    }

    @Test
    void validate_tokenBinding_with_status_null_test() {
        TokenBinding tokenBinding = new TokenBinding(null, (String) null);

        assertThrows(ConstraintViolationException.class,
                () -> BeanAssertUtil.validate(tokenBinding)
        );
    }

    @Test
    void validate_attestationObject_test() {
        AttestationObject attestationObject = new AttestationObject(TestDataUtil.createAuthenticatorData(), TestAttestationStatementUtil.createFIDOU2FAttestationStatement());

        BeanAssertUtil.validate(attestationObject);
    }

    @Test
    void validate_attestationObject_with_null_test() {
        assertThrows(ConstraintViolationException.class,
                () -> BeanAssertUtil.validate((AttestationObject) null)
        );
    }

    @Test
    void validate_attestationObject_with_authenticatorData_null_test() {
        AttestationObject attestationObject = new AttestationObject(null, TestAttestationStatementUtil.createFIDOU2FAttestationStatement());

        assertThrows(ConstraintViolationException.class,
                () -> BeanAssertUtil.validate(attestationObject)
        );
    }

    @Test
    void validate_attestationObject_with_attestationStatement_null_test() {
        AttestationObject attestationObject = new AttestationObject(TestDataUtil.createAuthenticatorData(), null);

        assertThrows(ConstraintViolationException.class,
                () -> BeanAssertUtil.validate(attestationObject)
        );
    }
}
