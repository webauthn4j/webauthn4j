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
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class HMACGetSecretAuthenticatorInputTest {

    @Test
    void getter_test(){
        COSEKey key = mock(COSEKey.class);
        HMACGetSecretAuthenticatorInput instance = new HMACGetSecretAuthenticatorInput(key, new byte[32], new byte[32], PinProtocolVersion.VERSION_1);
        assertThat(instance.getKeyAgreement()).isEqualTo(key);
        assertThat(instance.getSaltAuth()).isEqualTo(new byte[32]);
        assertThat(instance.getSaltEnc()).isEqualTo(new byte[32]);
        assertThat(instance.getPinUvAuthProtocol()).isEqualTo(PinProtocolVersion.VERSION_1);
    }

    @Test
    void getter_test_without_pinUvAuthProtocol(){
        COSEKey key = mock(COSEKey.class);
        HMACGetSecretAuthenticatorInput instance = new HMACGetSecretAuthenticatorInput(key, new byte[32], new byte[32]);
        assertThat(instance.getKeyAgreement()).isEqualTo(key);
        assertThat(instance.getSaltAuth()).isEqualTo(new byte[32]);
        assertThat(instance.getSaltEnc()).isEqualTo(new byte[32]);
        assertThat(instance.getPinUvAuthProtocol()).isNull();
    }

    @Test
    void equals_hashCode_test(){
        COSEKey key = mock(COSEKey.class);
        HMACGetSecretAuthenticatorInput instanceA = new HMACGetSecretAuthenticatorInput(key, new byte[32], new byte[32], null);
        HMACGetSecretAuthenticatorInput instanceB = new HMACGetSecretAuthenticatorInput(key, new byte[32], new byte[32], null);
        assertThat(instanceA)
                .isEqualTo(instanceB)
                .hasSameHashCodeAs(instanceB);
    }

    @Test
    void equals_hashCode_test_with_diff(){
        COSEKey key = mock(COSEKey.class);
        HMACGetSecretAuthenticatorInput instanceA = new HMACGetSecretAuthenticatorInput(key, new byte[32], new byte[32], PinProtocolVersion.VERSION_1);
        HMACGetSecretAuthenticatorInput instanceB = new HMACGetSecretAuthenticatorInput(key, new byte[32], new byte[32], PinProtocolVersion.VERSION_2);
        HMACGetSecretAuthenticatorInput instanceC = new HMACGetSecretAuthenticatorInput(key, new byte[32], new byte[32], null);

        assertThat(instanceA).isNotEqualTo(instanceB);
        assertThat(instanceA).doesNotHaveSameHashCodeAs(instanceB);

        assertThat(instanceA).isNotEqualTo(instanceC);
        assertThat(instanceA).doesNotHaveSameHashCodeAs(instanceC);
    }

}