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
import com.webauthn4j.data.extension.CredentialProtectionPolicy;
import com.webauthn4j.util.HexUtil;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AuthenticationExtensionsAuthenticatorInputsTest {

    private CborConverter cborConverter = new ObjectConverter().getCborConverter();

    @Test
    void registration_variant_test() {
        AuthenticationExtensionsAuthenticatorInputs.BuilderForRegistration builder = new AuthenticationExtensionsAuthenticatorInputs.BuilderForRegistration();
        builder.setUvm(true);
        builder.setCredProtect(CredentialProtectionPolicy.USER_VERIFICATION_OPTIONAL);
        builder.set("unknown", 1);
        AuthenticationExtensionsAuthenticatorInputs<RegistrationExtensionAuthenticatorInput> target = builder.build();

        assertThat(target.getKeys()).containsExactlyInAnyOrder("uvm", "credProtect", "unknown");

        assertThat(target.getUvm()).isTrue();
        assertThat(target.getCredProtect()).isEqualTo(CredentialProtectionPolicy.USER_VERIFICATION_OPTIONAL);
        assertThat(target.getUnknownKeys()).containsExactly("unknown");

        assertThat((Boolean)target.getValue("uvm")).isTrue();
        assertThat(target.getValue("credProtect")).isEqualTo(CredentialProtectionPolicy.USER_VERIFICATION_OPTIONAL);
        assertThat(target.getValue("unknown")).isEqualTo(1);
        assertThat(target.getValue("invalid")).isNull();

        assertThat(target.getExtension(UserVerificationMethodExtensionAuthenticatorInput.class)).isNotNull();
        assertThat(target.getExtension(UserVerificationMethodExtensionAuthenticatorInput.class).getIdentifier()).isEqualTo("uvm");
        assertThat(target.getExtension(UserVerificationMethodExtensionAuthenticatorInput.class).getUvm()).isTrue();
        assertThat(target.getExtension(CredentialProtectionExtensionAuthenticatorInput.class).getCredProtect()).isEqualTo(CredentialProtectionPolicy.USER_VERIFICATION_OPTIONAL);
    }

    @Test
    void authentication_variant_test() {
        AuthenticationExtensionsAuthenticatorInputs.BuilderForAuthentication builder = new AuthenticationExtensionsAuthenticatorInputs.BuilderForAuthentication();
        builder.setUvm(true);
        builder.set("unknown", 1);
        AuthenticationExtensionsAuthenticatorInputs<AuthenticationExtensionAuthenticatorInput> target = builder.build();

        assertThat(target.getKeys()).containsExactlyInAnyOrder("uvm", "unknown");

        assertThat(target.getUvm()).isTrue();
        assertThat(target.getUnknownKeys()).containsExactly("unknown");

        assertThat((Boolean)target.getValue("uvm")).isTrue();
        assertThat(target.getValue("unknown")).isEqualTo(1);
        assertThat(target.getValue("invalid")).isNull();

        assertThat(target.getExtension(UserVerificationMethodExtensionAuthenticatorInput.class)).isNotNull();
        assertThat(target.getExtension(UserVerificationMethodExtensionAuthenticatorInput.class).getIdentifier()).isEqualTo("uvm");
        assertThat(target.getExtension(UserVerificationMethodExtensionAuthenticatorInput.class).getUvm()).isTrue();

    }

    @Test
    void serialize_registration_test(){
        AuthenticationExtensionsAuthenticatorInputs.BuilderForRegistration builder = new AuthenticationExtensionsAuthenticatorInputs.BuilderForRegistration();
        builder.setCredProtect(CredentialProtectionPolicy.USER_VERIFICATION_OPTIONAL);
        AuthenticationExtensionsAuthenticatorInputs<RegistrationExtensionAuthenticatorInput> registrationExtensions = builder.build();
        byte[] bytes = cborConverter.writeValueAsBytes(registrationExtensions);
        assertThat(HexUtil.encodeToString(bytes)).isEqualTo("BF6B6372656450726F7465637401FF");
    }

    @Test
    void deserialize_registration_test(){
        AuthenticationExtensionsAuthenticatorInputs<RegistrationExtensionAuthenticatorInput> instance =
                cborConverter.readValue(HexUtil.decode("BF6B6372656450726F7465637401FF"), new TypeReference<AuthenticationExtensionsAuthenticatorInputs<RegistrationExtensionAuthenticatorInput>>() {});
        assertThat(instance.getCredProtect()).isEqualTo(CredentialProtectionPolicy.USER_VERIFICATION_OPTIONAL);
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