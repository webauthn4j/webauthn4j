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

package com.webauthn4j.data.extension.client;

import org.junit.jupiter.api.Test;

import java.util.HashMap;

import static org.assertj.core.api.Assertions.assertThat;

class AuthenticationExtensionsClientInputsTest {

    @Test
    void registration_variant_test() {
        AuthenticationExtensionsClientInputs.BuilderForRegistration builder = new AuthenticationExtensionsClientInputs.BuilderForRegistration();
        builder.setCredProps(true);
        builder.setUvm(true);
        builder.setUnknowns(new HashMap<>());
        AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> target = builder.build();

        assertThat(target.getKeys()).containsExactlyInAnyOrder("credProps", "uvm");

        assertThat(target.getAppid()).isNull();
        assertThat(target.getAppidExclude()).isNull();
        assertThat(target.getUvm()).isTrue();
        assertThat(target.getCredProps()).isTrue();
        assertThat(target.getUnknownKeys()).isEmpty();

        assertThat(target.getValue("appid")).isNull();
        assertThat(target.getValue("appidExclude")).isNull();
        assertThat((Boolean)target.getValue("uvm")).isTrue();
        assertThat((Boolean)target.getValue("credProps")).isTrue();
        assertThat(target.getValue("invalid")).isNull();

        assertThat(target.getExtension(UserVerificationMethodExtensionClientInput.class)).isNotNull();
        assertThat(target.getExtension(UserVerificationMethodExtensionClientInput.class).getIdentifier()).isEqualTo("uvm");
        assertThat(target.getExtension(UserVerificationMethodExtensionClientInput.class).getUvm()).isTrue();
        assertThat(target.getExtension(CredentialPropertiesExtensionClientInput.class)).isNotNull();
        assertThat(target.getExtension(CredentialPropertiesExtensionClientInput.class).getIdentifier()).isEqualTo("credProps");
        assertThat(target.getExtension(CredentialPropertiesExtensionClientInput.class).getCredProps()).isTrue();
    }

    @Test
    void authentication_variant_test() {
        AuthenticationExtensionsClientInputs.BuilderForAuthentication builder = new AuthenticationExtensionsClientInputs.BuilderForAuthentication();
        builder.setAppid("dummyAppid");
        builder.setAppidExclude("dummyAppidExclude");
        builder.setUvm(true);
        builder.setUnknowns(new HashMap<>());
        AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput> target = builder.build();

        assertThat(target.getKeys()).containsExactlyInAnyOrder("appid", "appidExclude", "uvm");

        assertThat(target.getAppid()).isEqualTo("dummyAppid");
        assertThat(target.getAppidExclude()).isEqualTo("dummyAppidExclude");
        assertThat(target.getUvm()).isTrue();
        assertThat(target.getCredProps()).isNull();
        assertThat(target.getUnknownKeys()).isEmpty();

        assertThat(target.getValue("appid")).isEqualTo("dummyAppid");
        assertThat(target.getValue("appidExclude")).isEqualTo("dummyAppidExclude");
        assertThat((Boolean)target.getValue("uvm")).isTrue();
        assertThat(target.getValue("credProps")).isNull();
        assertThat(target.getValue("invalid")).isNull();

        assertThat(target.getExtension(FIDOAppIDExtensionClientInput.class)).isNotNull();
        assertThat(target.getExtension(FIDOAppIDExtensionClientInput.class).getIdentifier()).isEqualTo("appid");
        assertThat(target.getExtension(FIDOAppIDExtensionClientInput.class).getAppid()).isEqualTo("dummyAppid");
        assertThat(target.getExtension(FIDOAppIDExclusionExtensionClientInput.class)).isNotNull();
        assertThat(target.getExtension(FIDOAppIDExclusionExtensionClientInput.class).getIdentifier()).isEqualTo("appidExclude");
        assertThat(target.getExtension(FIDOAppIDExclusionExtensionClientInput.class).getAppidExclude()).isEqualTo("dummyAppidExclude");
        assertThat(target.getExtension(UserVerificationMethodExtensionClientInput.class)).isNotNull();
        assertThat(target.getExtension(UserVerificationMethodExtensionClientInput.class).getIdentifier()).isEqualTo("uvm");
        assertThat(target.getExtension(UserVerificationMethodExtensionClientInput.class).getUvm()).isTrue();

    }

    @Test
    void equals_hashCode_test() {
        AuthenticationExtensionsClientInputs.BuilderForAuthentication builder1 = new AuthenticationExtensionsClientInputs.BuilderForAuthentication();
        builder1.setAppid("dummyAppid");
        builder1.setAppidExclude("dummyAppidExclude");
        builder1.setUvm(true);
        builder1.setUnknowns(new HashMap<>());
        AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput> instance1 = builder1.build();
        AuthenticationExtensionsClientInputs.BuilderForAuthentication builder2 = new AuthenticationExtensionsClientInputs.BuilderForAuthentication();
        builder2.setAppid("dummyAppid");
        builder2.setAppidExclude("dummyAppidExclude");
        builder2.setUvm(true);
        builder2.setUnknowns(new HashMap<>());
        AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput> instance2 = builder2.build();

        assertThat(instance1)
                .isEqualTo(instance2)
                .hasSameHashCodeAs(instance2);
    }

}