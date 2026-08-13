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

package com.webauthn4j.converter.jackson.serializer.cbor;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.PublicKeyCredentialUserEntity;
import org.junit.jupiter.api.Test;
import tools.jackson.dataformat.cbor.CBORMapper;

import static org.assertj.core.api.Assertions.assertThat;

class PublicKeyCredentialUserEntitySerializerTest {

    private final ObjectConverter objectConverter = new ObjectConverter();
    private final CBORMapper cborMapper = objectConverter.getCborMapper();

    @Test
    void cbor_serialize_deserialize_test() {
        PublicKeyCredentialUserEntity original =
                new PublicKeyCredentialUserEntity(new byte[]{1, 2, 3, 4}, "user@example.com", "Example User");
        byte[] encoded = cborMapper.writeValueAsBytes(original);
        PublicKeyCredentialUserEntity decoded = cborMapper.readValue(encoded, PublicKeyCredentialUserEntity.class);
        assertThat(decoded).isEqualTo(original);
    }

    @Test
    void cbor_serialization_produces_definite_length_map() {
        PublicKeyCredentialUserEntity entity =
                new PublicKeyCredentialUserEntity(new byte[]{1, 2, 3, 4}, "user@example.com", "Example User");
        byte[] encoded = cborMapper.writeValueAsBytes(entity);
        // First byte should be a definite-length CBOR map (0xA0-0xBE), not indefinite (0xBF)
        int firstByte = encoded[0] & 0xFF;
        assertThat(firstByte).isLessThan(0xBF);
        assertThat(firstByte & 0xE0).isEqualTo(0xA0);
    }
}
