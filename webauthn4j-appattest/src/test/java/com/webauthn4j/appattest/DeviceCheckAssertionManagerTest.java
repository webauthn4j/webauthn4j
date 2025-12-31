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

package com.webauthn4j.appattest;

import com.webauthn4j.appattest.data.DCAssertion;
import com.webauthn4j.appattest.data.DCAssertionData;
import com.webauthn4j.appattest.data.DCAssertionRequest;
import com.webauthn4j.converter.AuthenticatorDataConverter;
import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.test.TestDataUtil;
import org.junit.jupiter.api.Test;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

class DeviceCheckAssertionManagerTest {

    private final ObjectConverter objectConverter = new ObjectConverter();
    private final AuthenticatorDataConverter authenticatorDataConverter = new AuthenticatorDataConverter(objectConverter);

    @Test
    void constructor_test() {
        assertThatCode(DeviceCheckAssertionManager::new).doesNotThrowAnyException();
        assertThatCode(() -> new DeviceCheckAssertionManager(Collections.emptyList())).doesNotThrowAnyException();
    }

    @Test
    void parse_DCAssertion_with_signature_null_authenticatorData_null_test() {
        DeviceCheckAssertionManager deviceCheckAssertionManager = new DeviceCheckAssertionManager();
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData = TestDataUtil.createAuthenticatorData();
        byte[] keyId = new byte[64];
        byte[] authenticatorDataBytes = authenticatorDataConverter.convert(authenticatorData);
        byte[] assertion = objectConverter.getCborMapper().writeValueAsBytes(new DCAssertion(new byte[32], authenticatorDataBytes));
        byte[] clientDataHash = new byte[32];
        DCAssertionData dcAssertionData = deviceCheckAssertionManager.parse(new DCAssertionRequest(keyId, assertion, clientDataHash));

        assertThat(dcAssertionData.getKeyId()).isEqualTo(new byte[64]);
        assertThat(dcAssertionData.getSignature()).isEqualTo(new byte[32]);
        assertThat(dcAssertionData.getAuthenticatorData()).isEqualTo(authenticatorData);
        assertThat(dcAssertionData.getClientDataHash()).isEqualTo(new byte[32]);
    }

}