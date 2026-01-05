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

import com.webauthn4j.converter.exception.DataConversionException;
import org.junit.jupiter.api.Test;
import tools.jackson.core.exc.StreamReadException;
import tools.jackson.databind.ObjectMapper;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JacksonUtilTest {

    @Test
    void shouldWrapJsonParseExceptionInDataConversionExceptionWhenReadingTree() {
        //Given
        ObjectMapper objectMapper = mock(ObjectMapper.class);
        when(objectMapper.readTree((byte[]) any())).thenThrow(StreamReadException.class);
        byte[] value = new byte[0];

        //When/Then
        assertThatThrownBy(() -> JacksonUtil.readTree(objectMapper, value)).isInstanceOf(DataConversionException.class);
    }

}
