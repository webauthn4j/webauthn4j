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

package com.webauthn4j.converter.jackson.deserializer;

import com.fasterxml.jackson.core.type.TypeReference;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorInputs;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorInput;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class HMACSecretAuthenticatorInputDeserializerTest {

    private final ObjectConverter objectConverter = new ObjectConverter();
    private final JsonConverter jsonConverter = objectConverter.getJsonConverter();

    @Test
    void test(){
        AuthenticationExtensionsAuthenticatorInputs<RegistrationExtensionAuthenticatorInput> createExtensions = jsonConverter.readValue("{\"hmac-secret\": true }", new TypeReference<AuthenticationExtensionsAuthenticatorInputs<RegistrationExtensionAuthenticatorInput>>(){});
        assertThat(createExtensions.getHMACCreateSecret()).isTrue();
        AuthenticationExtensionsAuthenticatorInputs<RegistrationExtensionAuthenticatorInput> getExtensions = jsonConverter.readValue("{\"hmac-secret\": {} }", new TypeReference<AuthenticationExtensionsAuthenticatorInputs<RegistrationExtensionAuthenticatorInput>>(){});
        assertThat(getExtensions.getHMACGetSecret()).isNotNull();
    }

}