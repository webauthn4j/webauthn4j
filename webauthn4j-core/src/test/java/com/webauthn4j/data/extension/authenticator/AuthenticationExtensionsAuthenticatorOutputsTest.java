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

import com.webauthn4j.data.KeyProtectionType;
import com.webauthn4j.data.MatcherProtectionType;
import com.webauthn4j.data.UserVerificationMethod;
import com.webauthn4j.data.extension.CredentialProtectionPolicy;
import com.webauthn4j.data.extension.HMACGetSecretOutput;
import com.webauthn4j.data.extension.UvmEntries;
import com.webauthn4j.data.extension.UvmEntry;
import org.junit.jupiter.api.Test;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;

class AuthenticationExtensionsAuthenticatorOutputsTest {

    @Test
    void registration_variant_test() {
        UvmEntries uvm = new UvmEntries(Collections.singletonList(new UvmEntry(UserVerificationMethod.FINGERPRINT, KeyProtectionType.SOFTWARE, MatcherProtectionType.ON_CHIP)));
        AuthenticationExtensionsAuthenticatorOutputs.BuilderForRegistration builder = new AuthenticationExtensionsAuthenticatorOutputs.BuilderForRegistration();
        builder.setUvm(uvm);
        builder.setCredProtect(CredentialProtectionPolicy.USER_VERIFICATION_REQUIRED);
        builder.setHmacCreateSecret(true);
        builder.set("unknown", 1);
        AuthenticationExtensionsAuthenticatorOutputs<RegistrationExtensionAuthenticatorOutput> target = builder.build();

        assertThat(target.getKeys()).containsExactlyInAnyOrder("uvm", "credProtect", "hmacCreateSecret", "unknown");

        assertThat(target.getUvm()).isEqualTo(uvm);
        assertThat(target.getCredProtect()).isEqualTo(CredentialProtectionPolicy.USER_VERIFICATION_REQUIRED);
        assertThat(target.getHmacCreateSecret()).isTrue();
        assertThat(target.getUnknownKeys()).containsExactly("unknown");

        assertThat(target.getValue("uvm")).isEqualTo(uvm);
        assertThat(target.getValue("credProtect")).isEqualTo(CredentialProtectionPolicy.USER_VERIFICATION_REQUIRED);
        assertThat((Boolean)target.getValue("hmacCreateSecret")).isTrue();
        assertThat(target.getValue("unknown")).isEqualTo(1);
        assertThat(target.getValue("invalid")).isNull();

        assertThat(target.getExtension(UserVerificationMethodExtensionAuthenticatorOutput.class)).isNotNull();
        assertThat(target.getExtension(UserVerificationMethodExtensionAuthenticatorOutput.class).getIdentifier()).isEqualTo("uvm");
        assertThat(target.getExtension(UserVerificationMethodExtensionAuthenticatorOutput.class).getUvm()).isEqualTo(uvm);
        assertThat(target.getExtension(CredentialProtectionExtensionAuthenticatorOutput.class)).isNotNull();
        assertThat(target.getExtension(CredentialProtectionExtensionAuthenticatorOutput.class).getIdentifier()).isEqualTo("credProtect");
        assertThat(target.getExtension(CredentialProtectionExtensionAuthenticatorOutput.class).getCredProtect()).isEqualTo(CredentialProtectionPolicy.USER_VERIFICATION_REQUIRED);
        assertThat(target.getExtension(HMACCreateSecretExtensionAuthenticatorOutput.class)).isNotNull();
        assertThat(target.getExtension(HMACCreateSecretExtensionAuthenticatorOutput.class).getIdentifier()).isEqualTo("hmac-secret");
        assertThat(target.getExtension(HMACCreateSecretExtensionAuthenticatorOutput.class).getHmacCreateSecret()).isTrue();
    }

    @Test
    void authentication_variant_test() {
        UvmEntries uvm = new UvmEntries(Collections.singletonList(new UvmEntry(UserVerificationMethod.FINGERPRINT, KeyProtectionType.SOFTWARE, MatcherProtectionType.ON_CHIP)));
        AuthenticationExtensionsAuthenticatorOutputs.BuilderForAuthentication builder = new AuthenticationExtensionsAuthenticatorOutputs.BuilderForAuthentication();
        builder.setUvm(uvm);
        builder.setHmacGetSecret(new HMACGetSecretOutput(new byte[32], new byte[32]));
        builder.set("unknown", 1);
        AuthenticationExtensionsAuthenticatorOutputs<AuthenticationExtensionAuthenticatorOutput> target = builder.build();

        assertThat(target.getKeys()).containsExactlyInAnyOrder("uvm", "hmacGetSecret", "unknown");

        assertThat(target.getUvm()).isEqualTo(uvm);
        assertThat(target.getHmacGetSecret()).isEqualTo(new HMACGetSecretOutput(new byte[32], new byte[32]));
        assertThat(target.getUnknownKeys()).containsExactly("unknown");

        assertThat(target.getValue("uvm")).isEqualTo(uvm);
        assertThat(target.getValue("hmacGetSecret")).isEqualTo(new HMACGetSecretOutput(new byte[32], new byte[32]));
        assertThat(target.getValue("unknown")).isEqualTo(1);
        assertThat(target.getValue("invalid")).isNull();

        assertThat(target.getExtension(UserVerificationMethodExtensionAuthenticatorOutput.class)).isNotNull();
        assertThat(target.getExtension(UserVerificationMethodExtensionAuthenticatorOutput.class).getIdentifier()).isEqualTo("uvm");
        assertThat(target.getExtension(UserVerificationMethodExtensionAuthenticatorOutput.class).getUvm()).isEqualTo(uvm);
        assertThat(target.getExtension(HMACGetSecretExtensionAuthenticatorOutput.class)).isNotNull();
        assertThat(target.getExtension(HMACGetSecretExtensionAuthenticatorOutput.class).getIdentifier()).isEqualTo("hmac-secret");
        assertThat(target.getExtension(HMACGetSecretExtensionAuthenticatorOutput.class).getHmacGetSecret()).isEqualTo(new HMACGetSecretOutput(new byte[32], new byte[32]));
    }

    @Test
    void equals_hashCode_test() {
        UvmEntries uvm = new UvmEntries(Collections.singletonList(new UvmEntry(UserVerificationMethod.FINGERPRINT, KeyProtectionType.SOFTWARE, MatcherProtectionType.ON_CHIP)));
        AuthenticationExtensionsAuthenticatorOutputs.BuilderForAuthentication builder1 = new AuthenticationExtensionsAuthenticatorOutputs.BuilderForAuthentication();
        builder1.setUvm(uvm);
        AuthenticationExtensionsAuthenticatorOutputs<AuthenticationExtensionAuthenticatorOutput> instance1 = builder1.build();
        AuthenticationExtensionsAuthenticatorOutputs.BuilderForAuthentication builder2 = new AuthenticationExtensionsAuthenticatorOutputs.BuilderForAuthentication();
        builder2.setUvm(uvm);
        AuthenticationExtensionsAuthenticatorOutputs<AuthenticationExtensionAuthenticatorOutput> instance2 = builder2.build();

        assertThat(instance1)
                .isEqualTo(instance2)
                .hasSameHashCodeAs(instance2);
    }


}