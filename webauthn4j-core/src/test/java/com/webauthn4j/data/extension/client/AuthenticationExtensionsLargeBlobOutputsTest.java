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

class AuthenticationExtensionsLargeBlobOutputsTest {

    private final JsonMapper jsonMapper = new ObjectConverter().getJsonMapper();

    @Test
    void constructor_with_supported() {
        AuthenticationExtensionsLargeBlobOutputs target = new AuthenticationExtensionsLargeBlobOutputs(true, null, null);
        assertThat(target.getSupported()).isTrue();
        assertThat(target.getBlob()).isNull();
        assertThat(target.getWritten()).isNull();
    }

    @Test
    void constructor_with_blob() {
        AuthenticationExtensionsLargeBlobOutputs target = new AuthenticationExtensionsLargeBlobOutputs(null, new byte[]{1, 2, 3}, null);
        assertThat(target.getSupported()).isNull();
        assertThat(target.getBlob()).isEqualTo(new byte[]{1, 2, 3});
        assertThat(target.getWritten()).isNull();
    }

    @Test
    void constructor_with_written() {
        AuthenticationExtensionsLargeBlobOutputs target = new AuthenticationExtensionsLargeBlobOutputs(null, null, true);
        assertThat(target.getSupported()).isNull();
        assertThat(target.getBlob()).isNull();
        assertThat(target.getWritten()).isTrue();
    }

    @Test
    void blob_is_defensively_copied() {
        byte[] original = {1, 2, 3};
        AuthenticationExtensionsLargeBlobOutputs target = new AuthenticationExtensionsLargeBlobOutputs(null, original, null);
        original[0] = 99;
        assertThat(target.getBlob()).isEqualTo(new byte[]{1, 2, 3});

        byte[] retrieved = target.getBlob();
        retrieved[0] = 99;
        assertThat(target.getBlob()).isEqualTo(new byte[]{1, 2, 3});
    }

    @Test
    void equals_and_hashCode() {
        AuthenticationExtensionsLargeBlobOutputs a = new AuthenticationExtensionsLargeBlobOutputs(true, null, null);
        AuthenticationExtensionsLargeBlobOutputs b = new AuthenticationExtensionsLargeBlobOutputs(true, null, null);
        AuthenticationExtensionsLargeBlobOutputs c = new AuthenticationExtensionsLargeBlobOutputs(false, null, null);
        AuthenticationExtensionsLargeBlobOutputs d = new AuthenticationExtensionsLargeBlobOutputs(null, new byte[]{1}, null);

        assertThat(a).isEqualTo(b).hasSameHashCodeAs(b).isNotEqualTo(c).isNotEqualTo(d).isNotEqualTo(null);
    }

    @Test
    void deserialization_with_supported() {
        String json = "{\"supported\":true}";
        AuthenticationExtensionsLargeBlobOutputs result = jsonMapper.readValue(json, AuthenticationExtensionsLargeBlobOutputs.class);
        assertThat(result.getSupported()).isTrue();
    }

    @Test
    void deserialization_with_blob() {
        String json = "{\"blob\":\"AQID\"}";
        AuthenticationExtensionsLargeBlobOutputs result = jsonMapper.readValue(json, AuthenticationExtensionsLargeBlobOutputs.class);
        assertThat(result.getBlob()).isEqualTo(new byte[]{1, 2, 3});
    }

    @Test
    void deserialization_with_written() {
        String json = "{\"written\":false}";
        AuthenticationExtensionsLargeBlobOutputs result = jsonMapper.readValue(json, AuthenticationExtensionsLargeBlobOutputs.class);
        assertThat(result.getWritten()).isFalse();
    }

    @Test
    void serialization_round_trip_with_blob() {
        AuthenticationExtensionsLargeBlobOutputs original = new AuthenticationExtensionsLargeBlobOutputs(null, new byte[]{7, 8, 9}, null);
        String json = jsonMapper.writeValueAsString(original);
        AuthenticationExtensionsLargeBlobOutputs restored = jsonMapper.readValue(json, AuthenticationExtensionsLargeBlobOutputs.class);
        assertThat(restored).isEqualTo(original);
    }

}
