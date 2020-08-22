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

import com.webauthn4j.data.AuthenticationData;
import com.webauthn4j.data.AuthenticationParameters;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.client.*;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.test.TestAttestationStatementUtil;
import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.validator.exception.ConstraintViolationException;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashSet;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class BeanAssertUtilTest {

    @Test
    void validate_RegistrationData_test() {
        RegistrationData registrationData = new RegistrationData(
                TestDataUtil.createAttestationObjectWithFIDOU2FAttestationStatement(),
                new byte[32],
                TestDataUtil.createClientData(ClientDataType.CREATE),
                new byte[32],
                new AuthenticationExtensionsClientOutputs<>(),
                new HashSet<>()
        );
        BeanAssertUtil.validate(registrationData);
    }

    @Test
    void validate_RegistrationData_with_null_test() {
        assertThrows(ConstraintViolationException.class,
                () -> BeanAssertUtil.validate((RegistrationData) null)
        );
    }

    @Test
    void validate_RegistrationData_with_attestationObject_null_test() {
        RegistrationData registrationData = new RegistrationData(
                null,
                new byte[32],
                TestDataUtil.createClientData(ClientDataType.CREATE),
                new byte[32],
                new AuthenticationExtensionsClientOutputs<>(),
                new HashSet<>()
        );
        assertThrows(ConstraintViolationException.class,
                () -> BeanAssertUtil.validate(registrationData)
        );
    }

    @Test
    void validate_RegistrationData_with_attestationObjectBytes_null_test() {
        RegistrationData registrationData = new RegistrationData(
                TestDataUtil.createAttestationObjectWithFIDOU2FAttestationStatement(),
                null,
                TestDataUtil.createClientData(ClientDataType.CREATE),
                new byte[32],
                new AuthenticationExtensionsClientOutputs<>(),
                new HashSet<>()
        );
        assertThrows(ConstraintViolationException.class,
                () -> BeanAssertUtil.validate(registrationData)
        );
    }

    @Test
    void validate_RegistrationData_with_collectedClientData_null_test() {
        RegistrationData registrationData = new RegistrationData(
                TestDataUtil.createAttestationObjectWithFIDOU2FAttestationStatement(),
                new byte[32],
                null,
                new byte[32],
                new AuthenticationExtensionsClientOutputs<>(),
                new HashSet<>()
        );
        assertThrows(ConstraintViolationException.class,
                () -> BeanAssertUtil.validate(registrationData)
        );
    }

    @Test
    void validate_RegistrationData_with_clientDataBytes_null_test() {
        RegistrationData registrationData = new RegistrationData(
                TestDataUtil.createAttestationObjectWithFIDOU2FAttestationStatement(),
                new byte[32],
                TestDataUtil.createClientData(ClientDataType.CREATE),
                null,
                new AuthenticationExtensionsClientOutputs<>(),
                new HashSet<>()
        );
        assertThrows(ConstraintViolationException.class,
                () -> BeanAssertUtil.validate(registrationData)
        );
    }

    @Test
    void validate_RegistrationData_with_clientExtensions_null_test() {
        RegistrationData registrationData = new RegistrationData(
                TestDataUtil.createAttestationObjectWithFIDOU2FAttestationStatement(),
                new byte[32],
                TestDataUtil.createClientData(ClientDataType.CREATE),
                new byte[32],
                null,
                new HashSet<>()
        );
        assertDoesNotThrow(
                () -> BeanAssertUtil.validate(registrationData)
        );
    }

    @Test
    void validate_RegistrationData_with_transports_null_test() {
        RegistrationData registrationData = new RegistrationData(
                TestDataUtil.createAttestationObjectWithFIDOU2FAttestationStatement(),
                new byte[32],
                TestDataUtil.createClientData(ClientDataType.CREATE),
                new byte[32],
                new AuthenticationExtensionsClientOutputs<>(),
                null
        );
        assertDoesNotThrow(
                () -> BeanAssertUtil.validate(registrationData)
        );
    }



    @Test
    void validate_RegistrationParameters_test() {
        RegistrationParameters registrationParameters = new RegistrationParameters(
                TestDataUtil.createServerProperty(),
                true
        );
        BeanAssertUtil.validate(registrationParameters);
    }

    @Test
    void validate_RegistrationParameters_with_null_test() {
        assertThrows(ConstraintViolationException.class,
                () -> BeanAssertUtil.validate((RegistrationParameters) null)
        );
    }

    @Test
    void validate_RegistrationParameters_with_serverProperty_null_test() {
        RegistrationParameters registrationParameters = new RegistrationParameters(
                null,
                true
        );
        assertThrows(ConstraintViolationException.class,
                () -> BeanAssertUtil.validate(registrationParameters)
        );
    }

    @Test
    void validate_AuthenticationData_test() {
        AuthenticationData authenticationData = new AuthenticationData(
                new byte[32],
                new byte[32],
                TestDataUtil.createAuthenticatorData(),
                new byte[32],
                TestDataUtil.createClientData(ClientDataType.GET),
                new byte[32],
                new AuthenticationExtensionsClientOutputs<>(),
                new byte[32]
        );
        BeanAssertUtil.validate(authenticationData);
    }

    @Test
    void validate_AuthenticationData_with_null_test() {

        assertThrows(ConstraintViolationException.class,
                () -> BeanAssertUtil.validate((AuthenticationData) null)
        );
    }

    @Test
    void validate_AuthenticationData_with_credentialId_null_test() {
        AuthenticationData authenticationData = new AuthenticationData(
                null,
                new byte[32],
                TestDataUtil.createAuthenticatorData(),
                new byte[32],
                TestDataUtil.createClientData(ClientDataType.GET),
                new byte[32],
                new AuthenticationExtensionsClientOutputs<>(),
                new byte[32]
        );
        assertThrows(ConstraintViolationException.class,
                () -> BeanAssertUtil.validate(authenticationData)
        );
    }

    @Test
    void validate_AuthenticationData_with_userHandle_null_test() {
        AuthenticationData authenticationData = new AuthenticationData(
                new byte[32],
                null,
                TestDataUtil.createAuthenticatorData(),
                new byte[32],
                TestDataUtil.createClientData(ClientDataType.GET),
                new byte[32],
                new AuthenticationExtensionsClientOutputs<>(),
                new byte[32]
        );
        assertDoesNotThrow(
                () -> BeanAssertUtil.validate(authenticationData)
        );
    }

    @Test
    void validate_AuthenticationData_with_authenticatorData_null_test() {
        AuthenticationData authenticationData = new AuthenticationData(
                new byte[32],
                new byte[32],
                null,
                new byte[32],
                TestDataUtil.createClientData(ClientDataType.GET),
                new byte[32],
                new AuthenticationExtensionsClientOutputs<>(),
                new byte[32]
        );
        assertThrows(ConstraintViolationException.class,
                () -> BeanAssertUtil.validate(authenticationData)
        );
    }

    @Test
    void validate_AuthenticationData_with_authenticatorDataBytes_null_test() {
        AuthenticationData authenticationData = new AuthenticationData(
                new byte[32],
                new byte[32],
                TestDataUtil.createAuthenticatorData(),
                null,
                TestDataUtil.createClientData(ClientDataType.GET),
                new byte[32],
                new AuthenticationExtensionsClientOutputs<>(),
                new byte[32]
        );
        assertThrows(ConstraintViolationException.class,
                () -> BeanAssertUtil.validate(authenticationData)
        );
    }

    @Test
    void validate_AuthenticationData_with_collectedClientData_null_test() {
        AuthenticationData authenticationData = new AuthenticationData(
                new byte[32],
                new byte[32],
                TestDataUtil.createAuthenticatorData(),
                new byte[32],
                null,
                new byte[32],
                new AuthenticationExtensionsClientOutputs<>(),
                new byte[32]
        );
        assertThrows(ConstraintViolationException.class,
                () -> BeanAssertUtil.validate(authenticationData)
        );
    }


    @Test
    void validate_AuthenticationData_with_clientDataBytes_null_test() {
        AuthenticationData authenticationData = new AuthenticationData(
                new byte[32],
                new byte[32],
                TestDataUtil.createAuthenticatorData(),
                new byte[32],
                TestDataUtil.createClientData(ClientDataType.GET),
                null,
                new AuthenticationExtensionsClientOutputs<>(),
                new byte[32]
        );
        assertThrows(ConstraintViolationException.class,
                () -> BeanAssertUtil.validate(authenticationData)
        );
    }

    @Test
    void validate_AuthenticationData_with_clientExtensions_null_test() {
        AuthenticationData authenticationData = new AuthenticationData(
                new byte[32],
                new byte[32],
                TestDataUtil.createAuthenticatorData(),
                new byte[32],
                TestDataUtil.createClientData(ClientDataType.GET),
                new byte[32],
                null,
                new byte[32]
        );
        assertDoesNotThrow(
                () -> BeanAssertUtil.validate(authenticationData)
        );
    }


    @Test
    void validate_AuthenticationData_with_signature_null_test() {
        AuthenticationData authenticationData = new AuthenticationData(
                new byte[32],
                new byte[32],
                TestDataUtil.createAuthenticatorData(),
                new byte[32],
                TestDataUtil.createClientData(ClientDataType.GET),
                new byte[32],
                new AuthenticationExtensionsClientOutputs<>(),
                null
        );
        assertThrows(ConstraintViolationException.class,
                () -> BeanAssertUtil.validate(authenticationData)
        );
    }

    @SuppressWarnings("deprecation")
    @Test
    void validate_AuthenticationParameters_test() {
        AuthenticationParameters authenticationParameters = new AuthenticationParameters(
                TestDataUtil.createServerProperty(),
                TestDataUtil.createAuthenticator(),
                true,
                true,
                new ArrayList<>()
        );
        BeanAssertUtil.validate(authenticationParameters);
    }

    @Test
    void validate_AuthenticationParameters_with_null_test() {
        assertThrows(ConstraintViolationException.class,
                () -> BeanAssertUtil.validate((AuthenticationParameters) null)
        );
    }

    @SuppressWarnings("deprecation")
    @Test
    void validate_AuthenticationParameters_with_serverProperty_null_test() {
        AuthenticationParameters authenticationParameters = new AuthenticationParameters(
                null,
                TestDataUtil.createAuthenticator(),
                true,
                true,
                new ArrayList<>()
        );
        assertThrows(ConstraintViolationException.class,
                () -> BeanAssertUtil.validate(authenticationParameters)
        );
    }

    @SuppressWarnings("deprecation")
    @Test
    void validate_AuthenticationParameters_with_authenticator_null_test() {
        AuthenticationParameters authenticationParameters = new AuthenticationParameters(
                TestDataUtil.createServerProperty(),
                null,
                true,
                true,
                new ArrayList<>()
        );
        assertThrows(ConstraintViolationException.class,
                () -> BeanAssertUtil.validate(authenticationParameters)
        );
    }

    @SuppressWarnings("deprecation")
    @Test
    void validate_AuthenticationParameters_with_expectedExtensionIds_null_test() {
        AuthenticationParameters authenticationParameters = new AuthenticationParameters(
                TestDataUtil.createServerProperty(),
                TestDataUtil.createAuthenticator(),
                true,
                true,
                null
        );
        assertDoesNotThrow(
                () -> BeanAssertUtil.validate(authenticationParameters)
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
