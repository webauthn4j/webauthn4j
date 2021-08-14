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


import com.fasterxml.jackson.core.type.TypeReference;
import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.data.extension.CredentialProtectionPolicy;
import com.webauthn4j.util.HexUtil;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

@SuppressWarnings("ConstantConditions")
class AuthenticationExtensionsAuthenticatorInputsTest {

    private final CborConverter cborConverter = new ObjectConverter().getCborConverter();

    @SuppressWarnings("java:S5961")
    @Test
    void registration_variant_test() {
        AuthenticationExtensionsAuthenticatorInputs.BuilderForRegistration builder = new AuthenticationExtensionsAuthenticatorInputs.BuilderForRegistration();
        builder.setUvm(true);
        builder.setCredProtect(CredentialProtectionPolicy.USER_VERIFICATION_OPTIONAL);
        builder.setHMACCreateSecret(true);
        builder.set("unknown", 1);
        AuthenticationExtensionsAuthenticatorInputs<RegistrationExtensionAuthenticatorInput> target = builder.build();

        assertThat(target.getKeys()).containsExactlyInAnyOrder("uvm", "credProtect", "hmac-secret", "unknown");

        assertThat(target.getUvm()).isTrue();
        assertThat(target.getCredProtect()).isEqualTo(CredentialProtectionPolicy.USER_VERIFICATION_OPTIONAL);
        assertThat((boolean)target.getHMACSecret()).isTrue();
        assertThat(target.getHMACCreateSecret()).isTrue();
        assertThat(target.getHMACGetSecret()).isNull();
        assertThat(target.getUnknownKeys()).containsExactly("unknown");

        assertThat((Boolean) target.getValue("uvm")).isTrue();
        assertThat(target.getValue("credProtect")).isEqualTo(CredentialProtectionPolicy.USER_VERIFICATION_OPTIONAL);
        assertThat((Boolean) target.getValue("hmac-secret")).isTrue();
        assertThat(target.getValue("hmacCreateSecret")).isNull(); // hmacCreateSecret and hmacGetSecret is not a key of HMACSecretAuthenticationExtensionAuthenticatorInput
        assertThat(target.getValue("hmacGetSecret")).isNull();
        assertThat(target.getValue("unknown")).isEqualTo(1);
        assertThat(target.getValue("invalid")).isNull();

        assertThat(target.getExtension(UserVerificationMethodExtensionAuthenticatorInput.class)).isNotNull();
        assertThat(target.getExtension(UserVerificationMethodExtensionAuthenticatorInput.class).getIdentifier()).isEqualTo("uvm");
        assertThat(target.getExtension(UserVerificationMethodExtensionAuthenticatorInput.class).getUvm()).isTrue();
        assertThat(target.getExtension(CredentialProtectionExtensionAuthenticatorInput.class).getCredProtect()).isEqualTo(CredentialProtectionPolicy.USER_VERIFICATION_OPTIONAL);
        HMACSecretRegistrationExtensionAuthenticatorInput hmacSecretRegistrationExtensionAuthenticatorInput = target.getExtension(HMACSecretRegistrationExtensionAuthenticatorInput.class);
        assertThat(hmacSecretRegistrationExtensionAuthenticatorInput).isNotNull();
        assertThat(hmacSecretRegistrationExtensionAuthenticatorInput.getIdentifier()).isEqualTo("hmac-secret");
        assertThat(hmacSecretRegistrationExtensionAuthenticatorInput.getValue()).isTrue();
        assertThat(hmacSecretRegistrationExtensionAuthenticatorInput.getValue("hmac-secret")).isTrue();
        assertThatThrownBy(()->hmacSecretRegistrationExtensionAuthenticatorInput.getValue("hmacCreateSecret")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(()->hmacSecretRegistrationExtensionAuthenticatorInput.getValue("hmacGetSecret")).isInstanceOf(IllegalArgumentException.class);
    }

    @SuppressWarnings("java:S5961")
    @Test
    void authentication_variant_test() {
        HMACGetSecretAuthenticatorInput hmacGetSecretAuthenticatorInput = new HMACGetSecretAuthenticatorInput(mock(COSEKey.class), new byte[16], new byte[16]);
        AuthenticationExtensionsAuthenticatorInputs.BuilderForAuthentication builder = new AuthenticationExtensionsAuthenticatorInputs.BuilderForAuthentication();
        builder.setUvm(true);
        builder.setHMACGetSecret(hmacGetSecretAuthenticatorInput);
        builder.set("unknown", 1);
        AuthenticationExtensionsAuthenticatorInputs<AuthenticationExtensionAuthenticatorInput> target = builder.build();

        assertThat(target.getKeys()).containsExactlyInAnyOrder("uvm", "hmac-secret", "unknown");

        assertThat(target.getUvm()).isTrue();
        assertThat((HMACGetSecretAuthenticatorInput)target.getHMACSecret()).isEqualTo(hmacGetSecretAuthenticatorInput);
        assertThat(target.getHMACCreateSecret()).isNull();
        assertThat(target.getHMACGetSecret()).isEqualTo(hmacGetSecretAuthenticatorInput);
        assertThat(target.getUnknownKeys()).containsExactly("unknown");

        assertThat((Boolean) target.getValue("uvm")).isTrue();
        assertThat(target.getValue("hmac-secret")).isEqualTo(hmacGetSecretAuthenticatorInput);
        assertThat(target.getValue("hmacCreateSecret")).isNull(); // hmacCreateSecret and hmacGetSecret is not a key of HMACSecretAuthenticationExtensionAuthenticatorInput
        assertThat(target.getValue("hmacGetSecret")).isNull();
        assertThat(target.getValue("unknown")).isEqualTo(1);
        assertThat(target.getValue("invalid")).isNull();

        assertThat(target.getExtension(UserVerificationMethodExtensionAuthenticatorInput.class)).isNotNull();
        assertThat(target.getExtension(UserVerificationMethodExtensionAuthenticatorInput.class).getIdentifier()).isEqualTo("uvm");
        assertThat(target.getExtension(UserVerificationMethodExtensionAuthenticatorInput.class).getUvm()).isTrue();
        HMACSecretAuthenticationExtensionAuthenticatorInput hmacSecretAuthenticationExtensionAuthenticatorInput = target.getExtension(HMACSecretAuthenticationExtensionAuthenticatorInput.class);
        assertThat(hmacSecretAuthenticationExtensionAuthenticatorInput).isNotNull();
        assertThat(hmacSecretAuthenticationExtensionAuthenticatorInput.getIdentifier()).isEqualTo("hmac-secret");
        assertThat(hmacSecretAuthenticationExtensionAuthenticatorInput.getValue()).isEqualTo(hmacGetSecretAuthenticatorInput);
        assertThat(hmacSecretAuthenticationExtensionAuthenticatorInput.getValue("hmac-secret")).isEqualTo(hmacGetSecretAuthenticatorInput);
        assertThatThrownBy(()->hmacSecretAuthenticationExtensionAuthenticatorInput.getValue("hmacCreateSecret")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(()->hmacSecretAuthenticationExtensionAuthenticatorInput.getValue("hmacGetSecret")).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void serialize_registration_test() {
        AuthenticationExtensionsAuthenticatorInputs.BuilderForRegistration builder = new AuthenticationExtensionsAuthenticatorInputs.BuilderForRegistration();
        builder.setCredProtect(CredentialProtectionPolicy.USER_VERIFICATION_OPTIONAL);
        builder.setHMACCreateSecret(true);
        AuthenticationExtensionsAuthenticatorInputs<RegistrationExtensionAuthenticatorInput> registrationExtensions = builder.build();
        byte[] bytes = cborConverter.writeValueAsBytes(registrationExtensions);
        assertThat(HexUtil.encodeToString(bytes)).isEqualTo("BF6B6372656450726F74656374016B686D61632D736563726574F5FF");
    }

    @Test
    void deserialize_registration_test() {
        AuthenticationExtensionsAuthenticatorInputs<RegistrationExtensionAuthenticatorInput> instance =
                cborConverter.readValue(HexUtil.decode("BF6B6372656450726F74656374016B686D61632D736563726574F5FF"), new TypeReference<AuthenticationExtensionsAuthenticatorInputs<RegistrationExtensionAuthenticatorInput>>() {
                });
        assertThat(instance.getCredProtect()).isEqualTo(CredentialProtectionPolicy.USER_VERIFICATION_OPTIONAL);
        assertThat(instance.getHMACCreateSecret()).isTrue();
    }

    @Test
    void equals_hashCode_test() {
        AuthenticationExtensionsAuthenticatorInputs.BuilderForAuthentication builder1 = new AuthenticationExtensionsAuthenticatorInputs.BuilderForAuthentication();
        builder1.setUvm(true);
        AuthenticationExtensionsAuthenticatorInputs<AuthenticationExtensionAuthenticatorInput> instance1 = builder1.build();
        AuthenticationExtensionsAuthenticatorInputs.BuilderForAuthentication builder2 = new AuthenticationExtensionsAuthenticatorInputs.BuilderForAuthentication();
        builder2.setUvm(true);
        AuthenticationExtensionsAuthenticatorInputs<AuthenticationExtensionAuthenticatorInput> instance2 = builder2.build();

        assertThat(instance1)
                .isEqualTo(instance2)
                .hasSameHashCodeAs(instance2);
    }


}