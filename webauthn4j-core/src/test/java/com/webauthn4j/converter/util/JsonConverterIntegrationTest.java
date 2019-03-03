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

package com.webauthn4j.converter.util;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

class JsonConverterIntegrationTest {

    @Test
    void constructor_with_customized_objectMapper_inherits_customization() {
        ObjectMapper jsonMapper = new ObjectMapper(new JsonFactory());
        ObjectMapper cborMapper = new ObjectMapper(new CBORFactory());
        SimpleModule module = new SimpleModule();
        module.addSerializer(TestData.class, new TestDataSerializer());
        jsonMapper.registerModule(module);
        JsonConverter jsonConverter = new JsonConverter(jsonMapper, cborMapper);
        assertThat(jsonConverter.writeValueAsString(new TestData())).isEqualTo("\"serialized by TestDataSerializer\"");
    }

    static class TestData {

    }

    static class TestDataSerializer extends StdSerializer<TestData> {

        TestDataSerializer() {
            super(TestData.class);
        }

        @Override
        public void serialize(TestData value, JsonGenerator gen, SerializerProvider provider) throws IOException {
            gen.writeString("serialized by TestDataSerializer");
        }
    }
}
