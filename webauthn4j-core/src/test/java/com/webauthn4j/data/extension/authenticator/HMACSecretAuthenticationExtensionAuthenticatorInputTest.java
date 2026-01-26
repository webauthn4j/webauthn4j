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

package com.webauthn4j.data.extension.authenticator;

import com.webauthn4j.data.PinProtocolVersion;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.data.attestation.authenticator.Curve;
import com.webauthn4j.data.attestation.authenticator.EC2COSEKey;
import com.webauthn4j.verifier.exception.ConstraintViolationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class HMACSecretAuthenticationExtensionAuthenticatorInputTest {

    private EC2COSEKey key;

    @BeforeEach
    void setup() {
        key = mock(EC2COSEKey.class);
        when(key.getCurve()).thenReturn(Curve.SECP256R1);
    }

    @Test
    void validate_failure_invalid_keyAgreement() {
        EC2COSEKey invalidKey = mock(EC2COSEKey.class);
        doThrow(new ConstraintViolationException("algorithm must not be null")).when(invalidKey).validate();
        when(invalidKey.getCurve()).thenReturn(Curve.SECP256R1);

        HMACGetSecretAuthenticatorInput input = new HMACGetSecretAuthenticatorInput(invalidKey, new byte[32], new byte[16], PinProtocolVersion.VERSION_1);
        assertThatThrownBy(new HMACSecretAuthenticationExtensionAuthenticatorInput(input)::validate)
                .isInstanceOf(ConstraintViolationException.class)
                .hasMessage("algorithm must not be null");
    }

    @Test
    void validate_success_protocol_v1() {
        // saltAuth=16, saltEnc=32
        HMACGetSecretAuthenticatorInput input1 = new HMACGetSecretAuthenticatorInput(key, new byte[32], new byte[16], PinProtocolVersion.VERSION_1);
        assertThatCode(new HMACSecretAuthenticationExtensionAuthenticatorInput(input1)::validate).doesNotThrowAnyException();

        // saltAuth=16, saltEnc=64
        HMACGetSecretAuthenticatorInput input2 = new HMACGetSecretAuthenticatorInput(key, new byte[64], new byte[16], PinProtocolVersion.VERSION_1);
        assertThatCode(new HMACSecretAuthenticationExtensionAuthenticatorInput(input2)::validate).doesNotThrowAnyException();
    }

    @Test
    void validate_success_protocol_v2() {
        // saltAuth=32, saltEnc=48
        HMACGetSecretAuthenticatorInput input1 = new HMACGetSecretAuthenticatorInput(key, new byte[48], new byte[32], PinProtocolVersion.VERSION_2);
        assertThatCode(new HMACSecretAuthenticationExtensionAuthenticatorInput(input1)::validate).doesNotThrowAnyException();

        // saltAuth=32, saltEnc=80
        HMACGetSecretAuthenticatorInput input2 = new HMACGetSecretAuthenticatorInput(key, new byte[80], new byte[32], PinProtocolVersion.VERSION_2);
        assertThatCode(new HMACSecretAuthenticationExtensionAuthenticatorInput(input2)::validate).doesNotThrowAnyException();
    }

    @Test
    void validate_success_protocol_unknown() {
        // null protocol: should follow Protocol 1 (saltAuth=16, saltEnc=32)
        HMACGetSecretAuthenticatorInput input1 = new HMACGetSecretAuthenticatorInput(key, new byte[32], new byte[16], null);
        assertThatCode(new HMACSecretAuthenticationExtensionAuthenticatorInput(input1)::validate).doesNotThrowAnyException();
    }

    @Test
    void validate_failure_protocol_unknown_with_v2_length() {
        // null protocol: Protocol 2 lengths should fail
        HMACGetSecretAuthenticatorInput input = new HMACGetSecretAuthenticatorInput(key, new byte[48], new byte[32], null);
        assertThatThrownBy(new HMACSecretAuthenticationExtensionAuthenticatorInput(input)::validate).isInstanceOf(ConstraintViolationException.class);
    }

    @Test
    void validate_failure_protocol_v1_invalid_length() {
        // Invalid saltEnc (48 is for V2)
        HMACGetSecretAuthenticatorInput inputEnc = new HMACGetSecretAuthenticatorInput(key, new byte[48], new byte[16], PinProtocolVersion.VERSION_1);
        assertThatThrownBy(new HMACSecretAuthenticationExtensionAuthenticatorInput(inputEnc)::validate).isInstanceOf(ConstraintViolationException.class);

        // Invalid saltAuth (32 is for V2)
        HMACGetSecretAuthenticatorInput inputAuth = new HMACGetSecretAuthenticatorInput(key, new byte[32], new byte[32], PinProtocolVersion.VERSION_1);
        assertThatThrownBy(new HMACSecretAuthenticationExtensionAuthenticatorInput(inputAuth)::validate).isInstanceOf(ConstraintViolationException.class);
    }

    @Test
    void validate_failure_protocol_v2_invalid_length() {
        // Invalid saltEnc (32 is for V1)
        HMACGetSecretAuthenticatorInput inputEnc = new HMACGetSecretAuthenticatorInput(key, new byte[32], new byte[32], PinProtocolVersion.VERSION_2);
        assertThatThrownBy(new HMACSecretAuthenticationExtensionAuthenticatorInput(inputEnc)::validate).isInstanceOf(ConstraintViolationException.class);

        // Invalid saltAuth (16 is for V1)
        HMACGetSecretAuthenticatorInput inputAuth = new HMACGetSecretAuthenticatorInput(key, new byte[48], new byte[16], PinProtocolVersion.VERSION_2);
        assertThatThrownBy(new HMACSecretAuthenticationExtensionAuthenticatorInput(inputAuth)::validate).isInstanceOf(ConstraintViolationException.class);
    }

    @Test
    void validate_failure_null_fields() {
        assertThatThrownBy(new HMACSecretAuthenticationExtensionAuthenticatorInput(null)::validate).isInstanceOf(ConstraintViolationException.class);
        assertThatThrownBy(new HMACSecretAuthenticationExtensionAuthenticatorInput(new HMACGetSecretAuthenticatorInput(null, new byte[32], new byte[32]))::validate).isInstanceOf(ConstraintViolationException.class);
        assertThatThrownBy(new HMACSecretAuthenticationExtensionAuthenticatorInput(new HMACGetSecretAuthenticatorInput(key, null, new byte[32]))::validate).isInstanceOf(ConstraintViolationException.class);
        assertThatThrownBy(new HMACSecretAuthenticationExtensionAuthenticatorInput(new HMACGetSecretAuthenticatorInput(key, new byte[32], null))::validate).isInstanceOf(ConstraintViolationException.class);
    }

}