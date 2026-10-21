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
import com.webauthn4j.appattest.data.ValidationCategory;
import com.webauthn4j.appattest.data.extension.AppleBundleVersion01ExtensionAuthenticatorOutput;
import com.webauthn4j.appattest.data.extension.AppleValidationCategory01ExtensionAuthenticatorOutput;
import com.webauthn4j.converter.AuthenticatorDataConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
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
    void parse_DCAssertion_test() {
        DeviceCheckAssertionManager deviceCheckAssertionManager = new DeviceCheckAssertionManager();
        AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData = TestDataUtil.createAppAttestAssertionAuthenticatorData();
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

    @Test
    void parse_extensions_with_default_constructor_test() {
        assertAppleExtensions(new DeviceCheckAssertionManager());
    }

    @Test
    void parse_without_ed_flag_returns_null_for_absent_apple_extensions_test() {
        assertAbsentAppleExtensions(AuthenticatorData.BIT_AT);
    }

    @Test
    void parse_with_ed_flag_without_extension_bytes_returns_null_for_absent_apple_extensions_test() {
        assertAbsentAppleExtensions((byte) (AuthenticatorData.BIT_AT | AuthenticatorData.BIT_ED));
    }

    @Test
    void parse_extensions_with_custom_validators_constructor_test() {
        assertAppleExtensions(new DeviceCheckAssertionManager(Collections.emptyList()));
    }

    private void assertAbsentAppleExtensions(byte flags) {
        AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData = TestDataUtil.createAppAttestAssertionAuthenticatorData();
        byte[] authenticatorDataBytes = authenticatorDataConverter.convert(authenticatorData);
        authenticatorDataBytes[32] = flags;
        byte[] assertion = objectConverter.getCborMapper().writeValueAsBytes(new DCAssertion(new byte[32], authenticatorDataBytes));

        DCAssertionData data = new DeviceCheckAssertionManager().parse(
                new DCAssertionRequest(new byte[32], assertion, new byte[32]));

        assertThat(data.getAuthenticatorData().getExtensions().getKeys()).isEmpty();
        assertThat(data.getAuthenticatorData().getExtensions().getExtension(AppleBundleVersion01ExtensionAuthenticatorOutput.class)).isNull();
        assertThat(data.getAuthenticatorData().getExtensions().getExtension(AppleValidationCategory01ExtensionAuthenticatorOutput.class)).isNull();
    }

    private void assertAppleExtensions(DeviceCheckAssertionManager manager) {
        ValidationCategory validationCategory = ValidationCategory.DEVELOPMENT;
        AuthenticationExtensionsAuthenticatorOutputs<AuthenticationExtensionAuthenticatorOutput> extensions =
                new AuthenticationExtensionsAuthenticatorOutputs.BuilderForAuthentication()
                        .setObjectConverter(DeviceCheckManager.createObjectConverter())
                        .set(AppleBundleVersion01ExtensionAuthenticatorOutput.ID, "1")
                        .set(AppleValidationCategory01ExtensionAuthenticatorOutput.ID, validationCategory)
                        .build();
        AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData = new AuthenticatorData<>(
                new byte[32], (byte) (AuthenticatorData.BIT_AT | AuthenticatorData.BIT_ED), 1, null, extensions);
        byte[] authenticatorDataBytes = authenticatorDataConverter.convert(authenticatorData);
        byte[] assertion = objectConverter.getCborMapper().writeValueAsBytes(new DCAssertion(new byte[32], authenticatorDataBytes));

        DCAssertionData data = manager.parse(new DCAssertionRequest(new byte[32], assertion, new byte[32]));

        assertThat(data.getAuthenticatorDataBytes()).isEqualTo(authenticatorDataBytes);
        assertThat(data.getAuthenticatorData().getAttestedCredentialData()).isNull();
        assertThat(data.getAuthenticatorData().getExtensions()
                .getExtension(AppleBundleVersion01ExtensionAuthenticatorOutput.class).getBundleVersion()).isEqualTo("1");
        assertThat(data.getAuthenticatorData().getExtensions()
                .getExtension(AppleValidationCategory01ExtensionAuthenticatorOutput.class).getValidationCategory()).isEqualTo(validationCategory);
    }

}
