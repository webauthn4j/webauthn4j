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

package com.webauthn4j.metadata.data.statement;

import com.webauthn4j.converter.util.ObjectConverter;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class FriendlyNamesTest {

    private final JsonMapper jsonMapper = new ObjectConverter().getJsonMapper();

    @Test
    void constructor_with_map_test() {
        Map<String, String> source = new HashMap<>();
        source.put("en-US", "FIDO Sample Security Key");
        FriendlyNames target = new FriendlyNames(source);
        assertThat(target).containsEntry("en-US", "FIDO Sample Security Key");
        assertThat(target).hasSize(1);
    }

    @Test
    void empty_constructor_test() {
        FriendlyNames target = new FriendlyNames();
        assertThat(target).isEmpty();
    }

    @Test
    void put_test() {
        FriendlyNames target = new FriendlyNames();
        assertThrows(UnsupportedOperationException.class,
                () -> target.put("key", "value")
        );
    }

    @Test
    void json_roundTrip_test() {
        Map<String, String> source = new HashMap<>();
        source.put("en-US", "FIDO Sample Security Key");
        source.put("ja-JP", "FIDOサンプルセキュリティキー");
        FriendlyNames original = new FriendlyNames(source);

        String json = jsonMapper.writeValueAsString(original);
        FriendlyNames deserialized = jsonMapper.readValue(json, FriendlyNames.class);

        assertThat(deserialized).hasSize(2);
        assertThat(deserialized).containsEntry("en-US", "FIDO Sample Security Key");
        assertThat(deserialized).containsEntry("ja-JP", "FIDOサンプルセキュリティキー");
        assertThat(deserialized).isEqualTo(original);
    }

    @Test
    void json_deserialize_test() {
        String json = "{\"en-US\": \"Security Key\", \"fr-FR\": \"Clé de sécurité\"}";
        FriendlyNames target = jsonMapper.readValue(json, FriendlyNames.class);
        assertThat(target).containsEntry("en-US", "Security Key");
        assertThat(target).containsEntry("fr-FR", "Clé de sécurité");
    }

    @Test
    void entrySet_remove_test() {
        Map<String, String> source = new HashMap<>();
        source.put("key", "value");
        FriendlyNames target = new FriendlyNames(source);
        assertThrows(UnsupportedOperationException.class,
                () -> target.entrySet().remove(target.entrySet().iterator().next())
        );
    }
}
