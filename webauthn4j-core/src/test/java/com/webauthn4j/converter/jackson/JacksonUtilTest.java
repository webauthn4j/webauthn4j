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

package com.webauthn4j.converter.jackson;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.webauthn4j.converter.exception.DataConversionException;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.UncheckedIOException;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JacksonUtilTest {

    @Test
    void readTree_with_IOException_test() throws IOException {
        ObjectMapper objectMapper = mock(ObjectMapper.class);
        when(objectMapper.readTree((byte[]) any())).thenThrow(IOException.class);
        byte[] value = new byte[0];
        assertThatThrownBy(() -> JacksonUtil.readTree(objectMapper, value)).isInstanceOf(UncheckedIOException.class);
    }

    @Test
    void readTree_with_JsonParseException_test() throws IOException {
        ObjectMapper objectMapper = mock(ObjectMapper.class);
        when(objectMapper.readTree((byte[]) any())).thenThrow(JsonParseException.class);
        byte[] value = new byte[0];
        assertThatThrownBy(() -> JacksonUtil.readTree(objectMapper, value)).isInstanceOf(DataConversionException.class);
    }

    @Test
    void binaryValue_test() throws IOException {
        JsonNode jsonNode = mock(JsonNode.class);
        when(jsonNode.binaryValue()).thenThrow(IOException.class);
        assertThatThrownBy(() -> JacksonUtil.binaryValue(jsonNode)).isInstanceOf(UncheckedIOException.class);
    }

}