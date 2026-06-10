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

package com.webauthn4j.data;

import com.webauthn4j.converter.util.ObjectConverter;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PublicKeyCredentialClientCapabilitiesTest {

    private final JsonMapper jsonMapper = new ObjectConverter().getJsonMapper();

    @Test
    void deserialize_test() {
        TestDTO dto = jsonMapper.readValue("{\"capabilities\":{\"conditionalCreate\":true,\"hybridTransport\":false}}", TestDTO.class);
        assertThat(dto.capabilities)
                .containsEntry(ClientCapability.CONDITIONAL_CREATE, true)
                .containsEntry(ClientCapability.HYBRID_TRANSPORT, false);
    }

    @Test
    void deserialize_test_with_unknown_value() {
        assertDoesNotThrow(
                () -> jsonMapper.readValue("{\"capabilities\":{\"unknown\":true}}", TestDTO.class)
        );
    }

    @Test
    void put_test() {
        PublicKeyCredentialClientCapabilities target = new PublicKeyCredentialClientCapabilities();
        assertThrows(UnsupportedOperationException.class,
                () -> target.put(ClientCapability.CONDITIONAL_CREATE, true)
        );
    }

    @Test
    void entrySet_remove_test() {
        Map<ClientCapability, Boolean> source = new HashMap<>();
        source.put(ClientCapability.CONDITIONAL_CREATE, true);
        PublicKeyCredentialClientCapabilities target = new PublicKeyCredentialClientCapabilities(source);
        assertThrows(UnsupportedOperationException.class,
                () -> target.entrySet().remove(target.entrySet().iterator().next())
        );
    }

    static class TestDTO {
        @SuppressWarnings("WeakerAccess")
        public PublicKeyCredentialClientCapabilities capabilities;
    }
}
