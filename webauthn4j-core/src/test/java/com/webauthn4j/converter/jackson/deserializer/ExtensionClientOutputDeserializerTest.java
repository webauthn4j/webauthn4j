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

package com.webauthn4j.converter.jackson.deserializer;

import com.fasterxml.jackson.core.type.TypeReference;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.extension.client.CredentialPropertiesExtensionClientOutput;
import com.webauthn4j.data.extension.client.ExtensionClientOutput;
import com.webauthn4j.data.extension.client.FIDOAppIDExtensionClientOutput;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.AssertionsForInterfaceTypes.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

class ExtensionClientOutputDeserializerTest {

    @Test
    void deserialize_test_with_JSON_data() {
        ObjectConverter objectConverter = new ObjectConverter();
        JsonConverter jsonConverter = objectConverter.getJsonConverter();

        Map<String, ExtensionClientOutput<?>> extensionOutputs =
                jsonConverter.readValue(
                        "{ " +
                                "\"appid\": true, " +
                                "\"credProps\": {\"rk\": true }, " +
                                "\"txAuthSimple\": \"authorization message\", " +
                                "\"txAuthGeneric\": { \"contentType\": \"image/png\", \"content\": null }, " +
                                "\"authnSel\": true, " +
                                "\"exts\": [\"exts\", \"authnSel\"], " +
                                "\"uvi\": [], " +
                                "\"loc\": { \"latitude\": 0, \"longitude\":0, \"accuracy\": 1 }, " +
                                "\"biometricPerfBounds\": true " +
                                "}",
                        new TypeReference<Map<String, ExtensionClientOutput<?>>>() {
                        }
                );

        assertAll(
                () -> assertThat(extensionOutputs).containsKeys(
                        FIDOAppIDExtensionClientOutput.ID,
                        CredentialPropertiesExtensionClientOutput.ID
                ),
                () -> assertThat(extensionOutputs).containsValues(
                        new FIDOAppIDExtensionClientOutput(true),
                        new CredentialPropertiesExtensionClientOutput(new CredentialPropertiesExtensionClientOutput.CredentialPropertiesOutput(true))
                )
        );
    }
}
