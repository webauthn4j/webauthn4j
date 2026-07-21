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

package com.webauthn4j.data.extension.client;

import com.webauthn4j.converter.util.ObjectConverter;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;

class AuthenticationExtensionsPRFOutputsTest {

    private final JsonMapper jsonMapper = new ObjectConverter().getJsonMapper();

    @Test
    void constructor_with_enabled_only() {
        AuthenticationExtensionsPRFOutputs target = new AuthenticationExtensionsPRFOutputs(true, null);
        assertThat(target.getEnabled()).isTrue();
        assertThat(target.getResults()).isNull();
    }

    @Test
    void constructor_with_results_only() {
        AuthenticationExtensionsPRFValues results = new AuthenticationExtensionsPRFValues(new byte[]{1}, null);
        AuthenticationExtensionsPRFOutputs target = new AuthenticationExtensionsPRFOutputs(null, results);
        assertThat(target.getEnabled()).isNull();
        assertThat(target.getResults()).isEqualTo(results);
    }

    @Test
    void constructor_with_enabled_and_results() {
        AuthenticationExtensionsPRFValues results = new AuthenticationExtensionsPRFValues(new byte[]{1}, new byte[]{2});
        AuthenticationExtensionsPRFOutputs target = new AuthenticationExtensionsPRFOutputs(true, results);
        assertThat(target.getEnabled()).isTrue();
        assertThat(target.getResults()).isEqualTo(results);
    }

    @Test
    void equals_and_hashCode() {
        AuthenticationExtensionsPRFOutputs a = new AuthenticationExtensionsPRFOutputs(true, null);
        AuthenticationExtensionsPRFOutputs b = new AuthenticationExtensionsPRFOutputs(true, null);
        AuthenticationExtensionsPRFOutputs c = new AuthenticationExtensionsPRFOutputs(false, null);
        assertThat(a).isEqualTo(b).isNotEqualTo(c).isNotEqualTo(null);
        assertThat(a.hashCode()).isEqualTo(b.hashCode());
    }

    @Test
    void deserialization_with_enabled() {
        String json = "{\"enabled\":true}";
        AuthenticationExtensionsPRFOutputs result = jsonMapper.readValue(json, AuthenticationExtensionsPRFOutputs.class);
        assertThat(result.getEnabled()).isTrue();
        assertThat(result.getResults()).isNull();
    }

    @Test
    void deserialization_with_results() {
        String json = "{\"results\":{\"first\":\"AQID\",\"second\":\"BAUG\"}}";
        AuthenticationExtensionsPRFOutputs result = jsonMapper.readValue(json, AuthenticationExtensionsPRFOutputs.class);
        assertThat(result.getResults()).isNotNull();
        assertThat(result.getResults().getFirst()).isEqualTo(new byte[]{1, 2, 3});
        assertThat(result.getResults().getSecond()).isEqualTo(new byte[]{4, 5, 6});
    }

    @Test
    void serialization_round_trip() {
        AuthenticationExtensionsPRFValues results = new AuthenticationExtensionsPRFValues(new byte[]{1}, new byte[]{2});
        AuthenticationExtensionsPRFOutputs original = new AuthenticationExtensionsPRFOutputs(true, results);
        String json = jsonMapper.writeValueAsString(original);
        AuthenticationExtensionsPRFOutputs restored = jsonMapper.readValue(json, AuthenticationExtensionsPRFOutputs.class);
        assertThat(restored).isEqualTo(original);
    }

}
