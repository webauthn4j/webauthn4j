/*
 * Copyright 2002-2018 the original author or authors.
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

package com.webauthn4j.converter.jackson.deserializer.cbor;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorInputs;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorInput;
import org.junit.jupiter.api.Test;
import tools.jackson.core.exc.StreamReadException;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Test for HMACSecretAuthenticatorInputDeserializer
 */
class HMACSecretAuthenticatorInputDeserializerTest {

    private final ObjectConverter objectConverter = new ObjectConverter();
    private final JsonMapper jsonMapper = objectConverter.getJsonMapper();

    @Test
    void shouldDeserializeHMACCreateSecret() {
        // Given
        String json = "{\"hmac-secret\": true }";

        // When
        AuthenticationExtensionsAuthenticatorInputs<RegistrationExtensionAuthenticatorInput> createExtensions =
                jsonMapper.readValue(json, new TypeReference<AuthenticationExtensionsAuthenticatorInputs<RegistrationExtensionAuthenticatorInput>>(){});

        // Then
        assertThat(createExtensions.getHMACCreateSecret()).isTrue();
    }

    @Test
    void shouldDeserializeHMACGetSecret() {
        // Given
        String json = "{\"hmac-secret\": {} }";

        // When
        AuthenticationExtensionsAuthenticatorInputs<RegistrationExtensionAuthenticatorInput> getExtensions =
                jsonMapper.readValue(json, new TypeReference<AuthenticationExtensionsAuthenticatorInputs<RegistrationExtensionAuthenticatorInput>>(){});

        // Then
        assertThat(getExtensions.getHMACGetSecret()).isNotNull();
    }

    @Test
    void shouldThrowExceptionForInvalidInput() {
        // Given
        String invalidJson = "{invalid-json}";

        // When
        // Then
        assertThatThrownBy(() -> jsonMapper.readValue(invalidJson,
            new TypeReference<AuthenticationExtensionsAuthenticatorInputs<RegistrationExtensionAuthenticatorInput>>(){}))
                .isInstanceOf(StreamReadException.class);
    }

    @Test
    void shouldThrowExceptionForNullInput() {
        // Given
        String input = null;

        // When
        // Then
        assertThatThrownBy(() -> jsonMapper.readValue(input,
            new TypeReference<AuthenticationExtensionsAuthenticatorInputs<RegistrationExtensionAuthenticatorInput>>(){}))
                .isInstanceOf(IllegalArgumentException.class);
    }
}