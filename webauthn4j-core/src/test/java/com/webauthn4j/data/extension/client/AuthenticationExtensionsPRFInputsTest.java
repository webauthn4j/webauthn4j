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

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class AuthenticationExtensionsPRFInputsTest {

    private final JsonMapper jsonMapper = new ObjectConverter().getJsonMapper();

    @Test
    void constructor_with_eval_only() {
        AuthenticationExtensionsPRFValues eval = new AuthenticationExtensionsPRFValues(new byte[]{1}, null);
        AuthenticationExtensionsPRFInputs target = new AuthenticationExtensionsPRFInputs(eval, null);
        assertThat(target.getEval()).isEqualTo(eval);
        assertThat(target.getEvalByCredential()).isNull();
    }

    @Test
    void constructor_with_evalByCredential() {
        AuthenticationExtensionsPRFValues values = new AuthenticationExtensionsPRFValues(new byte[]{1}, null);
        Map<String, AuthenticationExtensionsPRFValues> evalByCredential = Map.of("credId123", values);
        AuthenticationExtensionsPRFInputs target = new AuthenticationExtensionsPRFInputs(null, evalByCredential);
        assertThat(target.getEval()).isNull();
        assertThat(target.getEvalByCredential()).containsKey("credId123");
    }

    @Test
    void equals_and_hashCode() {
        AuthenticationExtensionsPRFValues eval = new AuthenticationExtensionsPRFValues(new byte[]{1}, null);
        AuthenticationExtensionsPRFInputs a = new AuthenticationExtensionsPRFInputs(eval, null);
        AuthenticationExtensionsPRFInputs b = new AuthenticationExtensionsPRFInputs(eval, null);
        AuthenticationExtensionsPRFInputs c = new AuthenticationExtensionsPRFInputs(null, null);
        assertThat(a).isEqualTo(b).isNotEqualTo(c).isNotEqualTo(null);
        assertThat(a.hashCode()).isEqualTo(b.hashCode());
    }

    @Test
    void deserialization_with_eval() {
        String json = "{\"eval\":{\"first\":\"AQ\"}}";
        AuthenticationExtensionsPRFInputs result = jsonMapper.readValue(json, AuthenticationExtensionsPRFInputs.class);
        assertThat(result.getEval()).isNotNull();
        assertThat(result.getEval().getFirst()).isEqualTo(new byte[]{1});
    }

    @Test
    void deserialization_with_evalByCredential() {
        String json = "{\"evalByCredential\":{\"credId\":{\"first\":\"AQ\",\"second\":\"Ag\"}}}";
        AuthenticationExtensionsPRFInputs result = jsonMapper.readValue(json, AuthenticationExtensionsPRFInputs.class);
        assertThat(result.getEvalByCredential()).containsKey("credId");
        assertThat(result.getEvalByCredential().get("credId").getFirst()).isEqualTo(new byte[]{1});
        assertThat(result.getEvalByCredential().get("credId").getSecond()).isEqualTo(new byte[]{2});
    }

    @Test
    void serialization_round_trip() {
        AuthenticationExtensionsPRFValues eval = new AuthenticationExtensionsPRFValues(new byte[]{1, 2}, new byte[]{3, 4});
        AuthenticationExtensionsPRFValues credValues = new AuthenticationExtensionsPRFValues(new byte[]{5}, null);
        AuthenticationExtensionsPRFInputs original = new AuthenticationExtensionsPRFInputs(eval, Map.of("cred1", credValues));
        String json = jsonMapper.writeValueAsString(original);
        AuthenticationExtensionsPRFInputs restored = jsonMapper.readValue(json, AuthenticationExtensionsPRFInputs.class);
        assertThat(restored).isEqualTo(original);
    }

}
