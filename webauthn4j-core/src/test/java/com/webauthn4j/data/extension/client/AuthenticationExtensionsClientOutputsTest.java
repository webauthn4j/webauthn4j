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

package com.webauthn4j.data.extension.client;

import com.webauthn4j.data.KeyProtectionType;
import com.webauthn4j.data.MatcherProtectionType;
import com.webauthn4j.data.UserVerificationMethod;
import com.webauthn4j.data.extension.HMACGetSecretOutput;
import com.webauthn4j.data.extension.UvmEntries;
import com.webauthn4j.data.extension.UvmEntry;
import org.junit.jupiter.api.Test;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;

class AuthenticationExtensionsClientOutputsTest {

    @Test
    void registration_variant_test() {
        CredentialPropertiesOutput credProps = new CredentialPropertiesOutput(true);
        UvmEntries uvm = new UvmEntries(Collections.singletonList(new UvmEntry(UserVerificationMethod.FINGERPRINT, KeyProtectionType.SOFTWARE, MatcherProtectionType.ON_CHIP)));
        AuthenticationExtensionsClientOutputs.BuilderForRegistration builder = new AuthenticationExtensionsClientOutputs.BuilderForRegistration();
        builder.setCredProps(credProps);
        builder.setUvm(uvm);
        builder.setHmacCreateSecret(true);
        builder.set("unknown", 1);
        AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> target = builder.build();

        assertThat(target.getKeys()).containsExactlyInAnyOrder("credProps", "uvm", "hmacCreateSecret", "unknown");

        assertThat(target.getAppid()).isNull();
        assertThat(target.getUvm()).isEqualTo(uvm);
        assertThat(target.getCredProps()).isEqualTo(credProps);
        assertThat(target.getHmacCreateSecret()).isTrue();
        assertThat(target.getValue("unknown")).isEqualTo(1);

        assertThat(target.getUnknownKeys()).containsExactly("unknown");

        assertThat(target.getValue("appid")).isNull();
        assertThat(target.getValue("uvm")).isEqualTo(uvm);
        assertThat(target.getValue("credProps")).isEqualTo(credProps);
        assertThat((Boolean) target.getValue("hmacCreateSecret")).isTrue();
        assertThat(target.getValue("invalid")).isNull();

        assertThat(target.getExtension(UserVerificationMethodExtensionClientOutput.class)).isNotNull();
        assertThat(target.getExtension(UserVerificationMethodExtensionClientOutput.class).getIdentifier()).isEqualTo("uvm");
        assertThat(target.getExtension(UserVerificationMethodExtensionClientOutput.class).getUvm()).isEqualTo(uvm);
        assertThat(target.getExtension(CredentialPropertiesExtensionClientOutput.class)).isNotNull();
        assertThat(target.getExtension(CredentialPropertiesExtensionClientOutput.class).getIdentifier()).isEqualTo("credProps");
        assertThat(target.getExtension(CredentialPropertiesExtensionClientOutput.class).getCredProps()).isEqualTo(credProps);
        assertThat(target.getExtension(HMACCreateSecretExtensionClientOutput.class)).isNotNull();
        assertThat(target.getExtension(HMACCreateSecretExtensionClientOutput.class).getIdentifier()).isEqualTo("hmac-secret");
        assertThat(target.getExtension(HMACCreateSecretExtensionClientOutput.class).getHmacCreateSecret()).isTrue();
    }

    @Test
    void authentication_variant_test() {
        UvmEntries uvm = new UvmEntries(Collections.singletonList(new UvmEntry(UserVerificationMethod.FINGERPRINT, KeyProtectionType.SOFTWARE, MatcherProtectionType.ON_CHIP)));
        AuthenticationExtensionsClientOutputs.BuilderForAuthentication builder = new AuthenticationExtensionsClientOutputs.BuilderForAuthentication();
        builder.setAppid(true);
        builder.setUvm(uvm);
        builder.setHmacGetSecret(new HMACGetSecretOutput(new byte[32], new byte[32]));
        builder.set("unknown", "data");
        AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput> target = builder.build();

        assertThat(target.getKeys()).containsExactlyInAnyOrder("appid", "uvm", "hmacGetSecret", "unknown");

        assertThat(target.getAppid()).isTrue();
        assertThat(target.getUvm()).isEqualTo(uvm);
        assertThat(target.getCredProps()).isNull();
        assertThat(target.getHmacGetSecret()).isEqualTo(new HMACGetSecretOutput(new byte[32], new byte[32]));
        assertThat(target.getUnknownKeys()).containsExactly("unknown");

        assertThat((Boolean)target.getValue("appid")).isTrue();
        assertThat(target.getValue("uvm")).isEqualTo(uvm);
        assertThat(target.getValue("credProps")).isNull();
        assertThat(target.getValue("hmacGetSecret")).isEqualTo(new HMACGetSecretOutput(new byte[32], new byte[32]));
        assertThat(target.getValue("unknown")).isEqualTo("data");
        assertThat(target.getValue("invalid")).isNull();

        assertThat(target.getExtension(FIDOAppIDExtensionClientOutput.class)).isNotNull();
        assertThat(target.getExtension(FIDOAppIDExtensionClientOutput.class).getIdentifier()).isEqualTo("appid");
        assertThat(target.getExtension(FIDOAppIDExtensionClientOutput.class).getAppid()).isTrue();
        assertThat(target.getExtension(UserVerificationMethodExtensionClientOutput.class)).isNotNull();
        assertThat(target.getExtension(UserVerificationMethodExtensionClientOutput.class).getIdentifier()).isEqualTo("uvm");
        assertThat(target.getExtension(UserVerificationMethodExtensionClientOutput.class).getUvm()).isEqualTo(uvm);
        assertThat(target.getExtension(HMACGetSecretExtensionClientOutput.class)).isNotNull();
        assertThat(target.getExtension(HMACGetSecretExtensionClientOutput.class).getIdentifier()).isEqualTo("hmac-secret");
        assertThat(target.getExtension(HMACGetSecretExtensionClientOutput.class).getHmacGetSecret()).isEqualTo(new HMACGetSecretOutput(new byte[32], new byte[32]));

    }

    @Test
    void equals_hashCode_test() {
        UvmEntries uvm = new UvmEntries(Collections.singletonList(new UvmEntry(UserVerificationMethod.FINGERPRINT, KeyProtectionType.SOFTWARE, MatcherProtectionType.ON_CHIP)));
        AuthenticationExtensionsClientOutputs.BuilderForAuthentication builder1 = new AuthenticationExtensionsClientOutputs.BuilderForAuthentication();
        builder1.setAppid(true);
        builder1.setUvm(uvm);
        builder1.setHmacGetSecret(new HMACGetSecretOutput(new byte[32], new byte[32]));
        AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput> instance1 = builder1.build();
        AuthenticationExtensionsClientOutputs.BuilderForAuthentication builder2 = new AuthenticationExtensionsClientOutputs.BuilderForAuthentication();
        builder2.setAppid(true);
        builder2.setUvm(uvm);
        builder2.setHmacGetSecret(new HMACGetSecretOutput(new byte[32], new byte[32]));
        AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput> instance2 = builder2.build();

        assertThat(instance1)
                .isEqualTo(instance2)
                .hasSameHashCodeAs(instance2);
    }


}