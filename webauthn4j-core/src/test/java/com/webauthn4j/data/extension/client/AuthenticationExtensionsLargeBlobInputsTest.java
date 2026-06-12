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
import com.webauthn4j.data.extension.LargeBlobSupport;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;

class AuthenticationExtensionsLargeBlobInputsTest {

    private final JsonMapper jsonMapper = new ObjectConverter().getJsonMapper();

    @Test
    void constructor_with_support() {
        AuthenticationExtensionsLargeBlobInputs target = new AuthenticationExtensionsLargeBlobInputs(LargeBlobSupport.PREFERRED, null, null);
        assertThat(target.getSupport()).isEqualTo(LargeBlobSupport.PREFERRED);
        assertThat(target.getRead()).isNull();
        assertThat(target.getWrite()).isNull();
    }

    @Test
    void constructor_with_read() {
        AuthenticationExtensionsLargeBlobInputs target = new AuthenticationExtensionsLargeBlobInputs(null, true, null);
        assertThat(target.getSupport()).isNull();
        assertThat(target.getRead()).isTrue();
        assertThat(target.getWrite()).isNull();
    }

    @Test
    void constructor_with_write() {
        AuthenticationExtensionsLargeBlobInputs target = new AuthenticationExtensionsLargeBlobInputs(null, null, new byte[]{1, 2, 3});
        assertThat(target.getSupport()).isNull();
        assertThat(target.getRead()).isNull();
        assertThat(target.getWrite()).isEqualTo(new byte[]{1, 2, 3});
    }

    @Test
    void write_is_defensively_copied() {
        byte[] original = {1, 2, 3};
        AuthenticationExtensionsLargeBlobInputs target = new AuthenticationExtensionsLargeBlobInputs(null, null, original);
        original[0] = 99;
        assertThat(target.getWrite()).isEqualTo(new byte[]{1, 2, 3});

        byte[] retrieved = target.getWrite();
        retrieved[0] = 99;
        assertThat(target.getWrite()).isEqualTo(new byte[]{1, 2, 3});
    }

    @Test
    void equals_and_hashCode() {
        AuthenticationExtensionsLargeBlobInputs a = new AuthenticationExtensionsLargeBlobInputs(LargeBlobSupport.REQUIRED, null, null);
        AuthenticationExtensionsLargeBlobInputs b = new AuthenticationExtensionsLargeBlobInputs(LargeBlobSupport.REQUIRED, null, null);
        AuthenticationExtensionsLargeBlobInputs c = new AuthenticationExtensionsLargeBlobInputs(LargeBlobSupport.PREFERRED, null, null);

        assertThat(a).isEqualTo(b).isNotEqualTo(c).isNotEqualTo(null);
        assertThat(a.hashCode()).isEqualTo(b.hashCode());
    }

    @Test
    void deserialization_with_support() {
        String json = "{\"support\":\"required\"}";
        AuthenticationExtensionsLargeBlobInputs result = jsonMapper.readValue(json, AuthenticationExtensionsLargeBlobInputs.class);
        assertThat(result.getSupport()).isEqualTo(LargeBlobSupport.REQUIRED);
        assertThat(result.getRead()).isNull();
        assertThat(result.getWrite()).isNull();
    }

    @Test
    void deserialization_with_read() {
        String json = "{\"read\":true}";
        AuthenticationExtensionsLargeBlobInputs result = jsonMapper.readValue(json, AuthenticationExtensionsLargeBlobInputs.class);
        assertThat(result.getSupport()).isNull();
        assertThat(result.getRead()).isTrue();
    }

    @Test
    void deserialization_with_write() {
        String json = "{\"write\":\"AQID\"}";
        AuthenticationExtensionsLargeBlobInputs result = jsonMapper.readValue(json, AuthenticationExtensionsLargeBlobInputs.class);
        assertThat(result.getWrite()).isEqualTo(new byte[]{1, 2, 3});
    }

    @Test
    void serialization_round_trip_with_support() {
        AuthenticationExtensionsLargeBlobInputs original = new AuthenticationExtensionsLargeBlobInputs(LargeBlobSupport.PREFERRED, null, null);
        String json = jsonMapper.writeValueAsString(original);
        AuthenticationExtensionsLargeBlobInputs restored = jsonMapper.readValue(json, AuthenticationExtensionsLargeBlobInputs.class);
        assertThat(restored).isEqualTo(original);
    }

    @Test
    void serialization_round_trip_with_write() {
        AuthenticationExtensionsLargeBlobInputs original = new AuthenticationExtensionsLargeBlobInputs(null, null, new byte[]{4, 5, 6});
        String json = jsonMapper.writeValueAsString(original);
        AuthenticationExtensionsLargeBlobInputs restored = jsonMapper.readValue(json, AuthenticationExtensionsLargeBlobInputs.class);
        assertThat(restored).isEqualTo(original);
    }

}
