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

import com.webauthn4j.converter.jackson.deserializer.cbor.AuthenticationExtensionsAuthenticatorOutputsEnvelope;
import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.KeyProtectionType;
import com.webauthn4j.data.MatcherProtectionType;
import com.webauthn4j.data.UserVerificationMethod;
import com.webauthn4j.data.extension.CredentialProtectionPolicy;
import com.webauthn4j.data.extension.UvmEntries;
import com.webauthn4j.data.extension.UvmEntry;
import com.webauthn4j.util.HexUtil;
import org.junit.jupiter.api.Test;
import tools.jackson.core.type.TypeReference;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

@SuppressWarnings("ConstantConditions")
class AuthenticationExtensionsAuthenticatorOutputsTest {

    @SuppressWarnings("java:S5961")
    @Test
    void registration_variant_test() {
        UvmEntries uvm = new UvmEntries(Collections.singletonList(new UvmEntry(UserVerificationMethod.FINGERPRINT_INTERNAL, KeyProtectionType.SOFTWARE, MatcherProtectionType.ON_CHIP)));
        AuthenticationExtensionsAuthenticatorOutputs.BuilderForRegistration builder = new AuthenticationExtensionsAuthenticatorOutputs.BuilderForRegistration();
        builder.setUvm(uvm);
        builder.setCredProtect(CredentialProtectionPolicy.USER_VERIFICATION_REQUIRED);
        builder.setHMACCreateSecret(true);
        builder.set("unknown", 1);
        AuthenticationExtensionsAuthenticatorOutputs<RegistrationExtensionAuthenticatorOutput> target = builder.build();

        assertThat(target.getKeys()).containsExactlyInAnyOrder("uvm", "credProtect", "hmac-secret", "unknown");

        assertThat(target.getUvm()).isEqualTo(uvm);
        assertThat(target.getCredProtect()).isEqualTo(CredentialProtectionPolicy.USER_VERIFICATION_REQUIRED);
        assertThat((boolean)target.getHMACSecret()).isTrue();
        assertThat(target.getHMACCreateSecret()).isTrue();
        assertThat(target.getHMACGetSecret()).isNull();
        assertThat(target.getUnknownKeys()).containsExactly("unknown");

        assertThat(target.getValue("uvm")).isEqualTo(uvm);
        assertThat(target.getValue("credProtect")).isEqualTo(CredentialProtectionPolicy.USER_VERIFICATION_REQUIRED);
        assertThat((Boolean) target.getValue("hmac-secret")).isTrue();
        assertThat(target.getValue("hmacCreateSecret")).isNull(); // hmacCreateSecret and hmacGetSecret is not a key of HMACSecretAuthenticationExtensionAuthenticatorInput
        assertThat(target.getValue("hmacGetSecret")).isNull();
        assertThat(target.getValue("unknown")).isEqualTo(1);
        assertThat(target.getValue("invalid")).isNull();

        assertThat(target.getExtension(UserVerificationMethodExtensionAuthenticatorOutput.class)).isNotNull();
        assertThat(target.getExtension(UserVerificationMethodExtensionAuthenticatorOutput.class).getIdentifier()).isEqualTo("uvm");
        assertThat(target.getExtension(UserVerificationMethodExtensionAuthenticatorOutput.class).getUvm()).isEqualTo(uvm);
        assertThat(target.getExtension(CredentialProtectionExtensionAuthenticatorOutput.class).getCredProtect()).isEqualTo(CredentialProtectionPolicy.USER_VERIFICATION_REQUIRED);
        assertThat(target.getExtension(HMACSecretRegistrationExtensionAuthenticatorOutput.class)).isNotNull();
        assertThat(target.getExtension(HMACSecretRegistrationExtensionAuthenticatorOutput.class).getIdentifier()).isEqualTo("hmac-secret");
        assertThat(target.getExtension(HMACSecretRegistrationExtensionAuthenticatorOutput.class).getValue()).isTrue();
    }

    @SuppressWarnings("java:S5961")
    @Test
    void authentication_variant_test() {
        UvmEntries uvm = new UvmEntries(Collections.singletonList(new UvmEntry(UserVerificationMethod.FINGERPRINT_INTERNAL, KeyProtectionType.SOFTWARE, MatcherProtectionType.ON_CHIP)));
        AuthenticationExtensionsAuthenticatorOutputs.BuilderForAuthentication builder = new AuthenticationExtensionsAuthenticatorOutputs.BuilderForAuthentication();
        builder.setUvm(uvm);
        builder.setHMACGetSecret(new byte[32]);
        builder.set("unknown", 1);
        AuthenticationExtensionsAuthenticatorOutputs<AuthenticationExtensionAuthenticatorOutput> target = builder.build();

        assertThat(target.getKeys()).containsExactlyInAnyOrder("uvm", "hmac-secret", "unknown");

        assertThat(target.getUvm()).isEqualTo(uvm);
        assertThat((byte[])target.getHMACSecret()).isEqualTo(new byte[32]);
        assertThat(target.getHMACCreateSecret()).isNull();
        assertThat(target.getHMACGetSecret()).isEqualTo(new byte[32]);
        assertThat(target.getUnknownKeys()).containsExactly("unknown");

        assertThat(target.getValue("uvm")).isEqualTo(uvm);
        assertThat(target.getValue("hmac-secret")).isEqualTo(new byte[32]);
        assertThat(target.getValue("hmacCreateSecret")).isNull(); // hmacCreateSecret and hmacGetSecret is not a key of HMACSecretAuthenticationExtensionAuthenticatorInput
        assertThat(target.getValue("hmacGetSecret")).isNull();
        assertThat(target.getValue("unknown")).isEqualTo(1);
        assertThat(target.getValue("invalid")).isNull();

        assertThat(target.getExtension(UserVerificationMethodExtensionAuthenticatorOutput.class)).isNotNull();
        assertThat(target.getExtension(UserVerificationMethodExtensionAuthenticatorOutput.class).getIdentifier()).isEqualTo("uvm");
        assertThat(target.getExtension(UserVerificationMethodExtensionAuthenticatorOutput.class).getUvm()).isEqualTo(uvm);
        assertThat(target.getExtension(HMACSecretAuthenticationExtensionAuthenticatorOutput.class)).isNotNull();
        assertThat(target.getExtension(HMACSecretAuthenticationExtensionAuthenticatorOutput.class).getIdentifier()).isEqualTo("hmac-secret");
        assertThat(target.getExtension(HMACSecretAuthenticationExtensionAuthenticatorOutput.class).getValue()).isEqualTo(new byte[32]);

    }

    @Test
    void equals_hashCode_test() {
        UvmEntries uvm = new UvmEntries(Collections.singletonList(new UvmEntry(UserVerificationMethod.FINGERPRINT_INTERNAL, KeyProtectionType.SOFTWARE, MatcherProtectionType.ON_CHIP)));
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

    @SuppressWarnings("ResultOfMethodCallIgnored")
    @Test
    void toString_test(){
        UvmEntries uvm = new UvmEntries(Collections.singletonList(new UvmEntry(UserVerificationMethod.FINGERPRINT_INTERNAL, KeyProtectionType.SOFTWARE, MatcherProtectionType.ON_CHIP)));
        AuthenticationExtensionsAuthenticatorOutputs.BuilderForAuthentication builder = new AuthenticationExtensionsAuthenticatorOutputs.BuilderForAuthentication();
        builder.setUvm(uvm);
        builder.set("test", "value");
        AuthenticationExtensionsAuthenticatorOutputs<AuthenticationExtensionAuthenticatorOutput> instance = builder.build();
        assertThatCode(instance::toString).doesNotThrowAnyException();
    }

    @Test
    void deserialize_registration_test(){
        CborConverter cborConverter = new ObjectConverter().getCborConverter();

        byte[] testData = HexUtil.decode("A16B6372656450726F7465637402");
        AuthenticationExtensionsAuthenticatorOutputsEnvelope<ExtensionAuthenticatorOutput> envelope = cborConverter.readValue(testData, new TypeReference<>() {});
        byte[] serialized = cborConverter.writeValueAsBytes(envelope.getAuthenticationExtensionsAuthenticatorOutputs());
        assertThat(serialized).isEqualTo(testData);
    }

}
