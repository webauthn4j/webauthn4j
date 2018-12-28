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
import com.webauthn4j.response.extension.Coordinates;
import com.webauthn4j.response.extension.authenticator.GenericTransactionAuthorizationAuthenticatorExtensionOutput;
import com.webauthn4j.response.extension.authenticator.SimpleTransactionAuthorizationAuthenticatorExtensionOutput;
import com.webauthn4j.response.extension.client.*;
import com.webauthn4j.registry.Registry;
import org.junit.Test;

import java.io.IOException;
import java.util.Arrays;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

public class ClientExtensionOutputDeserializerTest {

    @Test
    public void deserialize_test_with_JSON_data() throws IOException {
        ObjectMapper objectMapper = new Registry().getJsonMapper();

        Map<String, ClientExtensionOutput> extensionOutputs =
                objectMapper.readValue(
                        "{ " +
                                "\"appid\": true, " +
                                "\"txAuthSimple\": \"authorization message\", " +
                                "\"txAuthGeneric\": { \"contentType\": \"image/png\", \"content\": null }, " +
                                "\"authnSel\": true, " +
                                "\"exts\": [\"exts\", \"authnSel\"], " +
                                "\"uvi\": [], " +
                                "\"loc\": { \"latitude\": 0, \"longitude\":0, \"accuracy\": 1 }, " +
                                "\"biometricPerfBounds\": true " +
                                "}",
                        new TypeReference<Map<String, ClientExtensionOutput>>() {
                        }
                );

        assertThat(extensionOutputs).containsKeys(
                FIDOAppIDClientExtensionOutput.ID,
                SimpleTransactionAuthorizationAuthenticatorExtensionOutput.ID,
                GenericTransactionAuthorizationAuthenticatorExtensionOutput.ID,
                AuthenticatorSelectionClientExtensionOutput.ID,
                SupportedExtensionsClientExtensionOutput.ID,
                UserVerificationIndexClientExtensionOutput.ID,
                LocationClientExtensionOutput.ID,
                BiometricAuthenticatorPerformanceBoundsClientExtensionOutput.ID
        );
        assertThat(extensionOutputs).containsValues(
                new FIDOAppIDClientExtensionOutput(true),
                new SimpleTransactionAuthorizationClientExtensionOutput("authorization message"),
                new GenericTransactionAuthorizationClientExtensionOutput(new GenericTransactionAuthorizationClientExtensionOutput.TxAuthnGenericArg("image/png", null)),
                new AuthenticatorSelectionClientExtensionOutput(true),
                new SupportedExtensionsClientExtensionOutput(Arrays.asList("exts", "authnSel")),
                new UserVerificationIndexClientExtensionOutput(new byte[0]),
                new LocationClientExtensionOutput(new Coordinates(0d, 0d, null, 1d, null, null, null)),
                new BiometricAuthenticatorPerformanceBoundsClientExtensionOutput(true)
        );
    }
}
