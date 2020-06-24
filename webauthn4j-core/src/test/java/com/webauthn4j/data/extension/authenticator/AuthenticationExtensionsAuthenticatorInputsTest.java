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


import org.junit.jupiter.api.Test;

import java.util.HashMap;

import static org.assertj.core.api.Assertions.assertThat;

class AuthenticationExtensionsAuthenticatorInputsTest {

    @Test
    void registration_variant_test() {
        AuthenticationExtensionsAuthenticatorInputs.BuilderForRegistration builder = new AuthenticationExtensionsAuthenticatorInputs.BuilderForRegistration();
        builder.setUvm(true);
        builder.setUnknowns(new HashMap<>());
        AuthenticationExtensionsAuthenticatorInputs<RegistrationExtensionAuthenticatorInput> target = builder.build();

        assertThat(target.getKeys()).containsExactlyInAnyOrder("uvm");

        assertThat(target.getUvm()).isTrue();
        assertThat(target.getUnknownKeys()).isEmpty();

        assertThat((Boolean)target.getValue("uvm")).isTrue();
        assertThat(target.getValue("invalid")).isNull();

        assertThat(target.getExtension(UserVerificationMethodExtensionAuthenticatorInput.class)).isNotNull();
        assertThat(target.getExtension(UserVerificationMethodExtensionAuthenticatorInput.class).getIdentifier()).isEqualTo("uvm");
        assertThat(target.getExtension(UserVerificationMethodExtensionAuthenticatorInput.class).getUvm()).isTrue();
    }

    @Test
    void authentication_variant_test() {
        AuthenticationExtensionsAuthenticatorInputs.BuilderForAuthentication builder = new AuthenticationExtensionsAuthenticatorInputs.BuilderForAuthentication();
        builder.setUvm(true);
        builder.setUnknowns(new HashMap<>());
        AuthenticationExtensionsAuthenticatorInputs<AuthenticationExtensionAuthenticatorInput> target = builder.build();

        assertThat(target.getKeys()).containsExactlyInAnyOrder("uvm");

        assertThat(target.getUvm()).isTrue();
        assertThat(target.getUnknownKeys()).isEmpty();

        assertThat((Boolean)target.getValue("uvm")).isTrue();
        assertThat(target.getValue("invalid")).isNull();

        assertThat(target.getExtension(UserVerificationMethodExtensionAuthenticatorInput.class)).isNotNull();
        assertThat(target.getExtension(UserVerificationMethodExtensionAuthenticatorInput.class).getIdentifier()).isEqualTo("uvm");
        assertThat(target.getExtension(UserVerificationMethodExtensionAuthenticatorInput.class).getUvm()).isTrue();

    }

    @Test
    void equals_hashCode_test() {
        AuthenticationExtensionsAuthenticatorInputs.BuilderForAuthentication builder1 = new AuthenticationExtensionsAuthenticatorInputs.BuilderForAuthentication();
        builder1.setUvm(true);
        builder1.setUnknowns(new HashMap<>());
        AuthenticationExtensionsAuthenticatorInputs<AuthenticationExtensionAuthenticatorInput> instance1 = builder1.build();
        AuthenticationExtensionsAuthenticatorInputs.BuilderForAuthentication builder2 = new AuthenticationExtensionsAuthenticatorInputs.BuilderForAuthentication();
        builder2.setUvm(true);
        builder2.setUnknowns(new HashMap<>());
        AuthenticationExtensionsAuthenticatorInputs<AuthenticationExtensionAuthenticatorInput> instance2 = builder2.build();

        assertThat(instance1)
                .isEqualTo(instance2)
                .hasSameHashCodeAs(instance2);
    }



}