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

package com.webauthn4j.converter.jackson.deserializer.json;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.extension.LargeBlobSupport;
import com.webauthn4j.data.extension.client.*;
import org.junit.jupiter.api.Test;
import tools.jackson.core.exc.StreamReadException;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

/**
 * Test for AuthenticationExtensionsClientInputsDeserializer
 */
@SuppressWarnings("ConstantConditions")
class AuthenticationExtensionsClientInputsDeserializerTest {

    private final ObjectConverter objectConverter = new ObjectConverter();
    private final JsonMapper jsonMapper = objectConverter.getJsonMapper();

    @Test
    void shouldDeserializeRegistrationExtensionInput() {
        //Given
        String json = "{ " +
                "\"credProps\": true " +
                "}";

        //When
        AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> extensionInputs =
                jsonMapper.readValue(
                        json,
                        new TypeReference<AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput>>() {
                        }
                );

        //Then
        assertAll(
                () -> assertThat(extensionInputs.getExtension(CredentialPropertiesExtensionClientInput.class).getValue()).isTrue()
        );
    }

    @Test
    void shouldDeserializeAuthenticationExtensionInput() {
        //Given
        String json = "{ " +
                "\"appid\": \"dummy\" " +
                "}";

        //When
        AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput> extensionInputs =
                jsonMapper.readValue(
                        json,
                        new TypeReference<AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput>>() {
                        }
                );

        //Then
        assertAll(
                () -> assertThat(extensionInputs.getExtension(FIDOAppIDExtensionClientInput.class).getValue()).isEqualTo("dummy")
        );
    }

    @Test
    void shouldDeserializeLargeBlobRegistrationInput() {
        //Given
        String json = "{ \"largeBlob\": { \"support\": \"preferred\" } }";

        //When
        AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> extensionInputs =
                jsonMapper.readValue(
                        json,
                        new TypeReference<AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput>>() {
                        }
                );

        //Then
        assertAll(
                () -> assertThat(extensionInputs.getExtension(LargeBlobExtensionClientInput.class).getValue().getSupport()).isEqualTo(LargeBlobSupport.PREFERRED)
        );
    }

    @Test
    void shouldDeserializeLargeBlobAuthenticationReadInput() {
        //Given
        String json = "{ \"largeBlob\": { \"read\": true } }";

        //When
        AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput> extensionInputs =
                jsonMapper.readValue(
                        json,
                        new TypeReference<AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput>>() {
                        }
                );

        //Then
        assertAll(
                () -> assertThat(extensionInputs.getExtension(LargeBlobExtensionClientInput.class).getValue().getRead()).isTrue()
        );
    }

    @Test
    void shouldDeserializeLargeBlobAuthenticationWriteInput() {
        //Given
        String json = "{ \"largeBlob\": { \"write\": \"AQID\" } }";

        //When
        AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput> extensionInputs =
                jsonMapper.readValue(
                        json,
                        new TypeReference<AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput>>() {
                        }
                );

        //Then
        assertAll(
                () -> assertThat(extensionInputs.getExtension(LargeBlobExtensionClientInput.class).getValue().getWrite()).isEqualTo(new byte[]{1, 2, 3})
        );
    }

    @Test
    void shouldDeserializePRFInput() {
        //Given
        String json = "{ \"prf\": { \"eval\": { \"first\": \"AQ\" } } }";

        //When
        AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> extensionInputs =
                jsonMapper.readValue(
                        json,
                        new TypeReference<AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput>>() {
                        }
                );

        //Then
        assertAll(
                () -> assertThat(extensionInputs.getExtension(PRFExtensionClientInput.class).getValue().getEval().getFirst()).isEqualTo(new byte[]{1})
        );
    }

    @Test
    void shouldThrowExceptionForInvalidInput() {
        //Given
        String invalidJson = "{invalid-json}";

        //Then
        assertThatThrownBy(() -> jsonMapper.readValue(invalidJson,
                new TypeReference<AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput>>(){}))
                .isInstanceOf(StreamReadException.class);
    }

    @Test
    void shouldThrowExceptionForNullInput() {
        //Then
        assertThatThrownBy(() -> jsonMapper.readValue((String)null,
                new TypeReference<AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput>>(){}))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
