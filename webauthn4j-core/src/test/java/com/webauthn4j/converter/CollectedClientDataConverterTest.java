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

package com.webauthn4j.converter;

import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.data.client.ClientDataType;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.util.Base64UrlUtil;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

class CollectedClientDataConverterTest {

    private JsonConverter jsonConverter = JsonConverter.INSTANCE;

    private CollectedClientDataConverter target = new CollectedClientDataConverter(jsonConverter);

    @Test
    void convert_deserialization_test() {
        //noinspection SpellCheckingInspection
        String clientDataJson = "{\"challenge\":\"tk31UH1ETGGTPj33OhOMzw\",\"origin\":\"http://localhost:8080\",\"tokenBinding\":{\"status\":\"not-supported\"},\"type\":\"webauthn.get\"}";
        String clientDataBase64UrlString = Base64UrlUtil.encodeToString(clientDataJson.getBytes(StandardCharsets.UTF_8));
        CollectedClientData collectedClientData = target.convert(clientDataBase64UrlString);
        assertAll(
                () -> assertThat(collectedClientData.getType()).isEqualTo(ClientDataType.GET),
                //noinspection SpellCheckingInspection
                () -> assertThat(collectedClientData.getChallenge()).isEqualTo(new DefaultChallenge("tk31UH1ETGGTPj33OhOMzw")),
                () -> assertThat(collectedClientData.getOrigin()).isEqualTo(new Origin("http://localhost:8080"))
        );
    }

    @Test
    void convert_null_test() {
        assertAll(
                () -> assertThat(target.convert((String) null)).isNull(),
                () -> assertThat(target.convert((byte[]) null)).isNull()
        );
    }

    @Test
    void convert_clientDataBase64UrlString_with_new_keys_test() {
        //noinspection SpellCheckingInspection
        String clientDataJson = "{\"challenge\":\"Tgup0LZZQKinvtQcZFYdRw\",\"new_keys_may_be_added_here\":\"do not compare clientDataJSON against a template. See https://goo.gl/yabPex\",\"origin\":\"http://localhost:8080\",\"tokenBinding\":{\"status\":\"not-supported\"},\"type\":\"webauthn.create\"}";
        String clientDataBase64UrlString = Base64UrlUtil.encodeToString(clientDataJson.getBytes(StandardCharsets.UTF_8));
        CollectedClientData collectedClientData = target.convert(clientDataBase64UrlString);
        assertAll(
                () -> assertThat(collectedClientData.getType()).isEqualTo(ClientDataType.CREATE),
                //noinspection SpellCheckingInspection
                () -> assertThat(collectedClientData.getChallenge()).isEqualTo(new DefaultChallenge("Tgup0LZZQKinvtQcZFYdRw")),
                () -> assertThat(collectedClientData.getOrigin()).isEqualTo(new Origin("http://localhost:8080"))
        );
    }

    @Test
    void convertToString_deserialization_test() {
        //noinspection SpellCheckingInspection
        String clientDataJson = "{\"challenge\":\"tk31UH1ETGGTPj33OhOMzw\",\"origin\":\"http://localhost:8080\",\"tokenBinding\":{\"status\":\"not-supported\"},\"type\":\"webauthn.get\"}";
        String clientDataBase64UrlString = Base64UrlUtil.encodeToString(clientDataJson.getBytes(StandardCharsets.UTF_8));
        CollectedClientData collectedClientData = target.convert(clientDataBase64UrlString);
        String result = target.convertToBase64UrlString(collectedClientData);
        //noinspection SpellCheckingInspection
        assertThat(result).isEqualTo("eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoidGszMVVIMUVUR0dUUGozM09oT016dyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsInRva2VuQmluZGluZyI6eyJzdGF0dXMiOiJub3Qtc3VwcG9ydGVkIn19");
    }
}
