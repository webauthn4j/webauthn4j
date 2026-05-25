/*
 * Copyright 2002-2018 the original author or authors.
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

package com.webauthn4j.metadata.converter.jackson.serializer;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.metadata.converter.jackson.WebAuthnMetadataJSONModule;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class MetadataAAGUIDSerializerTest {

    private final JsonMapper jsonMapper = new ObjectConverter().getJsonMapper().rebuild()
            .addModule(new WebAuthnMetadataJSONModule())
            .build();

    @Test
    void serialize_shouldWriteUUIDString() {
        AAGUID aaguid = new AAGUID("33c1642b-b5e9-423d-9add-5a0119c2a8b8");
        String json = jsonMapper.writeValueAsString(aaguid);
        assertThat(json).isEqualTo("\"33c1642b-b5e9-423d-9add-5a0119c2a8b8\"");
    }

    @Test
    void serialize_shouldRoundTrip() {
        AAGUID original = new AAGUID("33c1642b-b5e9-423d-9add-5a0119c2a8b8");
        String json = jsonMapper.writeValueAsString(original);
        AAGUID deserialized = jsonMapper.readValue(json, AAGUID.class);
        assertThat(deserialized).isEqualTo(original);
    }

    @SuppressWarnings("ConstantConditions")
    @Test
    void serialize_shouldThrowForNull() {
        MetadataAAGUIDSerializer serializer = new MetadataAAGUIDSerializer();
        assertThatThrownBy(() -> serializer.serialize(null, null, null))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
