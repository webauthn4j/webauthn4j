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

class AuthenticationExtensionsPRFValuesTest {

    private final JsonMapper jsonMapper = new ObjectConverter().getJsonMapper();

    @Test
    void constructor_with_first_only() {
        AuthenticationExtensionsPRFValues target = new AuthenticationExtensionsPRFValues(new byte[]{1, 2, 3}, null);
        assertThat(target.getFirst()).isEqualTo(new byte[]{1, 2, 3});
        assertThat(target.getSecond()).isNull();
    }

    @Test
    void constructor_with_first_and_second() {
        AuthenticationExtensionsPRFValues target = new AuthenticationExtensionsPRFValues(new byte[]{1}, new byte[]{2});
        assertThat(target.getFirst()).isEqualTo(new byte[]{1});
        assertThat(target.getSecond()).isEqualTo(new byte[]{2});
    }

    @Test
    void defensive_copy() {
        byte[] first = {1, 2, 3};
        byte[] second = {4, 5, 6};
        AuthenticationExtensionsPRFValues target = new AuthenticationExtensionsPRFValues(first, second);
        first[0] = 99;
        second[0] = 99;
        assertThat(target.getFirst()).isEqualTo(new byte[]{1, 2, 3});
        assertThat(target.getSecond()).isEqualTo(new byte[]{4, 5, 6});

        target.getFirst()[0] = 99;
        target.getSecond()[0] = 99;
        assertThat(target.getFirst()).isEqualTo(new byte[]{1, 2, 3});
        assertThat(target.getSecond()).isEqualTo(new byte[]{4, 5, 6});
    }

    @Test
    void equals_and_hashCode() {
        AuthenticationExtensionsPRFValues a = new AuthenticationExtensionsPRFValues(new byte[]{1}, new byte[]{2});
        AuthenticationExtensionsPRFValues b = new AuthenticationExtensionsPRFValues(new byte[]{1}, new byte[]{2});
        AuthenticationExtensionsPRFValues c = new AuthenticationExtensionsPRFValues(new byte[]{3}, null);
        assertThat(a).isEqualTo(b).isNotEqualTo(c).isNotEqualTo(null);
        assertThat(a.hashCode()).isEqualTo(b.hashCode());
    }

    @Test
    void deserialization_with_first_only() {
        String json = "{\"first\":\"AQID\"}";
        AuthenticationExtensionsPRFValues result = jsonMapper.readValue(json, AuthenticationExtensionsPRFValues.class);
        assertThat(result.getFirst()).isEqualTo(new byte[]{1, 2, 3});
        assertThat(result.getSecond()).isNull();
    }

    @Test
    void serialization_round_trip() {
        AuthenticationExtensionsPRFValues original = new AuthenticationExtensionsPRFValues(new byte[]{1, 2}, new byte[]{3, 4});
        String json = jsonMapper.writeValueAsString(original);
        AuthenticationExtensionsPRFValues restored = jsonMapper.readValue(json, AuthenticationExtensionsPRFValues.class);
        assertThat(restored).isEqualTo(original);
    }

}
