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
import com.fasterxml.jackson.databind.ObjectMapper;
import com.webauthn4j.converter.jackson.ObjectMapperUtil;
import com.webauthn4j.extension.client.*;
import org.junit.Test;

import java.io.IOException;
import java.util.Arrays;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

public class ClientExtensionOutputDeserializerTest {

    @Test
    public void deserialize_test_with_JSON_data() throws IOException {
        ObjectMapper objectMapper = ObjectMapperUtil.createWebAuthnClassesAwareJSONMapper(); // use JSON mapper to make test data readable

        Map<String, ClientExtensionOutput> extensionOutputs =
                objectMapper.readValue(
                        "{ " +
                                "\"appid\": true, " +
                                "\"txAuthSimple\": \"authorization message\", " +
                                "\"txAuthGeneric\": { \"contentType\": \"image/png\", \"content\": null }, " +
                                "\"authnSel\": [], " +
                                "\"exts\": [\"exts\", \"authnSel\"], " +
                                "\"uvi\": null, " +
                                "\"loc\": { \"latitude\": 0, \"longitude\":0, \"accuracy\": 1 }, " +
                                "\"biometricPerfBounds\": { \"FAR\": 0, \"FRR\":0 } " +
                                "}",
                        new TypeReference<Map<String, ClientExtensionOutput>>() {
                        }
                );

        assertThat(extensionOutputs).containsKeys(FIDOAppIDClientExtensionOutput.ID, SupportedExtensionsClientExtensionOutput.ID);
        assertThat(extensionOutputs).containsValues(
                new FIDOAppIDClientExtensionOutput(true),
                new SimpleTransactionAuthorizationClientExtensionOutput("authorization message"),
                new GenericTransactionAuthorizationClientExtensionOutput(new GenericTransactionAuthorizationClientExtensionOutput.TxAuthnGenericArg("image/png", null)),
                new SupportedExtensionsClientExtensionOutput(Arrays.asList("exts", "authnSel"))
        );
    }
}
