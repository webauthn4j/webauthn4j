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

package com.webauthn4j.converter.util;

import org.junit.jupiter.api.Test;
import tools.jackson.core.JsonGenerator;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.module.SimpleModule;
import tools.jackson.databind.ser.std.StdSerializer;

import static org.assertj.core.api.Assertions.assertThat;

class JsonConverterIntegrationTest {

    @Test
    void shouldInheritCustomizationFromObjectMapper() {
        //Given
        SimpleModule module = new SimpleModule();
        module.addSerializer(TestData.class, new TestDataSerializer());
        JsonMapper jsonMapper = JsonMapper.builder()
                .addModule(module)
                .build();

        //When
        JsonConverter jsonConverter = new JsonConverter(jsonMapper);

        //Then
        assertThat(jsonConverter.writeValueAsString(new TestData())).isEqualTo("\"serialized by TestDataSerializer\"");
    }

    static class TestData {

    }

    static class TestDataSerializer extends StdSerializer<TestData> {

        TestDataSerializer() {
            super(TestData.class);
        }

        @Override
        public void serialize(TestData value, JsonGenerator gen, SerializationContext provider) {
            gen.writeString("serialized by TestDataSerializer");
        }
    }
}
