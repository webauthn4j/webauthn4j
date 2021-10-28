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

package com.webauthn4j.converter.jackson.deserializer.json;

import com.fasterxml.jackson.core.type.TypeReference;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.extension.client.*;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

@SuppressWarnings("ConstantConditions")
class AuthenticationExtensionsClientInputsDeserializerTest {

    @Test
    void deserialize_test_with_registration_extension_JSON_data() {
        ObjectConverter objectConverter = new ObjectConverter();
        JsonConverter jsonConverter = objectConverter.getJsonConverter();

        AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> extensionInputs =
                jsonConverter.readValue(
                        "{ " +
                                "\"credProps\": true " +
                                "}",
                        new TypeReference<AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput>>() {
                        }
                );

        assertAll(
                () -> assertThat(extensionInputs.getExtension(CredentialPropertiesExtensionClientInput.class).getValue()).isTrue()
        );
    }

    @Test
    void deserialize_test_with_authentication_extension_JSON_data() {
        ObjectConverter objectConverter = new ObjectConverter();
        JsonConverter jsonConverter = objectConverter.getJsonConverter();
        AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput> extensionInputs =
                jsonConverter.readValue(
                        "{ " +
                                "\"appid\": \"dummy\" " +
                                "}",
                        new TypeReference<AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput>>() {
                        }
                );

        assertAll(
                () -> assertThat(extensionInputs.getExtension(FIDOAppIDExtensionClientInput.class).getValue()).isEqualTo("dummy")
        );
    }


}