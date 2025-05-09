/*
 * Copyright 2018 the original author or authors.
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

package com.webauthn4j.converter;

import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.client.ClientDataType;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.util.Base64UrlUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

@SuppressWarnings("ConstantConditions")
class CollectedClientDataConverterTest {

    // Common test data
    private static final String WEB_AUTH_GET_JSON = "{\"challenge\":\"tk31UH1ETGGTPj33OhOMzw\",\"origin\":\"http://localhost:8080\",\"crossOrigin\":true,\"tokenBinding\":{\"status\":\"not-supported\"},\"type\":\"webauthn.get\"}";
    private static final String WEB_AUTH_CREATE_WITH_NEW_KEYS_JSON = "{\"challenge\":\"Tgup0LZZQKinvtQcZFYdRw\",\"new_keys_may_be_added_here\":\"do not compare clientDataJSON against a template. See https://goo.gl/yabPex\",\"origin\":\"http://localhost:8080\",\"tokenBinding\":{\"status\":\"not-supported\"},\"type\":\"webauthn.create\"}";
    private static final String ANDROID_APK_KEY_HASH_JSON = "{\n" +
            "  \"type\": \"webauthn.create\",\n" +
            "  \"challenge\": \"AAABcXKin1fLrZx0o4RL64fs-RUVSxCu\",\n" +
            "  \"origin\": \"android:apk-key-hash:pNiP5iKyQ8JwgGOaKA1zGPUPJIS00H1xKCQcfIoGLck\",\n" +
            "  \"androidPackageName\": \"com.myrpid.app\"\n" +
            "}";
    private static final String ANDROID_APK_KEY_HASH_SHA256_JSON = "{\n" +
            "  \"type\": \"webauthn.create\",\n" +
            "  \"challenge\": \"AAABcXKin1fLrZx0o4RL64fs-RUVSxCu\",\n" +
            "  \"origin\": \"android:apk-key-hash-sha256:xT5ZucZJ9N7oq3j3awG8J/NlKf8trfo6AAJB8deuuNo=\",\n" +
            "  \"androidPackageName\": \"com.myrpid.app\"\n" +
            "}";

    private ObjectConverter objectConverter;
    private CollectedClientDataConverter target;

    @BeforeEach
    void setUp() {
        objectConverter = new ObjectConverter();
        target = new CollectedClientDataConverter(objectConverter);
    }

    @Nested
    class DeserializationTests {
        @Test
        void shouldDeserializeWebAuthGetClientData() {
            // Given
            String clientDataBase64UrlString = Base64UrlUtil.encodeToString(WEB_AUTH_GET_JSON.getBytes(StandardCharsets.UTF_8));
            
            // When
            CollectedClientData collectedClientData = target.convert(clientDataBase64UrlString);
            
            // Then
            assertAll(
                    () -> assertThat(collectedClientData.getType()).isEqualTo(ClientDataType.WEBAUTHN_GET),
                    () -> assertThat(collectedClientData.getChallenge()).isEqualTo(new DefaultChallenge("tk31UH1ETGGTPj33OhOMzw")),
                    () -> assertThat(collectedClientData.getOrigin()).isEqualTo(new Origin("http://localhost:8080")),
                    () -> assertThat(collectedClientData.getCrossOrigin()).isTrue()
            );
        }

        @Test
        void shouldDeserializeClientDataWithNewKeys() {
            // Given
            String clientDataBase64UrlString = Base64UrlUtil.encodeToString(WEB_AUTH_CREATE_WITH_NEW_KEYS_JSON.getBytes(StandardCharsets.UTF_8));
            
            // When
            CollectedClientData collectedClientData = target.convert(clientDataBase64UrlString);
            
            // Then
            assertAll(
                    () -> assertThat(collectedClientData.getType()).isEqualTo(ClientDataType.WEBAUTHN_CREATE),
                    () -> assertThat(collectedClientData.getChallenge()).isEqualTo(new DefaultChallenge("Tgup0LZZQKinvtQcZFYdRw")),
                    () -> assertThat(collectedClientData.getOrigin()).isEqualTo(new Origin("http://localhost:8080")),
                    () -> assertThat(collectedClientData.getCrossOrigin()).isNull()
            );
        }

        @Test
        void shouldDeserializeAndroidApkKeyHashClientData() {
            // Given
            String clientDataBase64UrlString = Base64UrlUtil.encodeToString(ANDROID_APK_KEY_HASH_JSON.getBytes(StandardCharsets.UTF_8));
            
            // When
            CollectedClientData collectedClientData = target.convert(clientDataBase64UrlString);
            
            // Then
            assertAll(
                    () -> assertThat(collectedClientData.getType()).isEqualTo(ClientDataType.WEBAUTHN_CREATE),
                    () -> assertThat(collectedClientData.getTokenBinding()).isNull(),
                    () -> assertThat(collectedClientData.getChallenge()).isEqualTo(new DefaultChallenge("AAABcXKin1fLrZx0o4RL64fs-RUVSxCu")),
                    () -> assertThat(collectedClientData.getOrigin()).isEqualTo(new Origin("android:apk-key-hash:pNiP5iKyQ8JwgGOaKA1zGPUPJIS00H1xKCQcfIoGLck"))
            );
        }

        @Test
        void shouldDeserializeAndroidApkKeyHashSha256ClientData() {
            // Given
            String clientDataBase64UrlString = Base64UrlUtil.encodeToString(ANDROID_APK_KEY_HASH_SHA256_JSON.getBytes(StandardCharsets.UTF_8));
            
            // When
            CollectedClientData collectedClientData = target.convert(clientDataBase64UrlString);
            
            // Then
            assertAll(
                    () -> assertThat(collectedClientData.getType()).isEqualTo(ClientDataType.WEBAUTHN_CREATE),
                    () -> assertThat(collectedClientData.getTokenBinding()).isNull(),
                    () -> assertThat(collectedClientData.getChallenge()).isEqualTo(new DefaultChallenge("AAABcXKin1fLrZx0o4RL64fs-RUVSxCu")),
                    () -> assertThat(collectedClientData.getOrigin()).isEqualTo(new Origin("android:apk-key-hash-sha256:xT5ZucZJ9N7oq3j3awG8J/NlKf8trfo6AAJB8deuuNo="))
            );
        }
    }

    @Nested
    class SerializationTests {
        @Test
        void shouldSerializeToBase64UrlString() {
            // Given
            String clientDataBase64UrlString = Base64UrlUtil.encodeToString(WEB_AUTH_GET_JSON.getBytes(StandardCharsets.UTF_8));
            CollectedClientData collectedClientData = target.convert(clientDataBase64UrlString);
            
            // When
            String result = target.convertToBase64UrlString(collectedClientData);
            
            // Then
            assertThat(result).isEqualTo("eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoidGszMVVIMUVUR0dUUGozM09oT016dyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjp0cnVlLCJ0b2tlbkJpbmRpbmciOnsic3RhdHVzIjoibm90LXN1cHBvcnRlZCJ9fQ");
        }
    }

    @Nested
    class ErrorHandlingTests {
        @Test
        void shouldThrowExceptionWhenInputIsNull() {
            // When/Then
            assertAll(
                    () -> assertThatThrownBy(() -> target.convert((String) null))
                            .isInstanceOf(DataConversionException.class),
                    () -> assertThatThrownBy(() -> target.convert((byte[]) null))
                            .isInstanceOf(DataConversionException.class),
                    () -> assertThatThrownBy(() -> target.convertToBytes(null))
                            .isInstanceOf(DataConversionException.class),
                    () -> assertThatThrownBy(() -> target.convertToBase64UrlString(null))
                            .isInstanceOf(DataConversionException.class)
            );
        }
    }
}
