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

import com.fasterxml.jackson.core.type.TypeReference;
import com.webauthn4j.registry.Registry;
import com.webauthn4j.util.Base64UrlUtil;
import org.junit.Test;

import java.io.UncheckedIOException;

import static org.assertj.core.api.Assertions.assertThat;

public class JsonConverterTest {

    private JsonConverter converter = new JsonConverter(new Registry().getJsonMapper());

    @Test
    public void readValue_test(){
        converter.readValue("{\"value\":\"dummy\"}", ConverterTestDto.class);
    }

    @Test(expected = UncheckedIOException.class)
    public void readValue_with_invalid_json_test(){
        converter.readValue("{value:\"dummy\"}", ConverterTestDto.class);
    }

    @Test
    public void readValue_with_TypeReference_test(){
        converter.readValue("{\"value\":\"dummy\"}", new TypeReference<ConverterTestDto>(){});
    }

    @Test(expected = UncheckedIOException.class)
    public void readValue_with_invalid_json_and_TypeReference_test(){
        converter.readValue("{value:\"dummy\"}", new TypeReference<ConverterTestDto>(){});
    }

    @Test
    public void writeValueAsString_test(){
        ConverterTestDto converterTestDto = new ConverterTestDto();
        converterTestDto.setValue("dummy");
        String str = converter.writeValueAsString(converterTestDto);
        assertThat(str).isEqualTo("{\"value\":\"dummy\"}");
    }

    @Test(expected = UncheckedIOException.class)
    public void writeValueAsString_with_invalid_dto_test(){
        ConverterTestInvalidDto converterTestInvalidDto = new ConverterTestInvalidDto();
        converterTestInvalidDto.setValue(new Object());
        converter.writeValueAsString(converterTestInvalidDto);
    }

    @Test
    public void writeValueAsBytes_test(){
        ConverterTestDto converterTestDto = new ConverterTestDto();
        converterTestDto.setValue("dummy");
        byte[] bytes = converter.writeValueAsBytes(converterTestDto);
        assertThat(Base64UrlUtil.encodeToString(bytes)).isEqualTo("eyJ2YWx1ZSI6ImR1bW15In0");
    }

    @Test(expected = UncheckedIOException.class)
    public void writeValueAsBytes_with_invalid_dto_test(){
        ConverterTestInvalidDto converterTestInvalidDto = new ConverterTestInvalidDto();
        converterTestInvalidDto.setValue(new Object());
        converter.writeValueAsBytes(converterTestInvalidDto);
    }


}
