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

package com.webauthn4j.converter;

import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.data.extension.client.ExtensionClientInput;
import com.webauthn4j.data.extension.client.FIDOAppIDExtensionClientInput;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AuthenticationExtensionsClientInputsConverterTest {

    private ObjectConverter objectConverter = new ObjectConverter();

    private AuthenticationExtensionsClientInputsConverter authenticationExtensionsClientInputsConverter = new AuthenticationExtensionsClientInputsConverter(objectConverter);


    @Test
    void convert_null_test() {
        assertThat(authenticationExtensionsClientInputsConverter.convert(null)).isNull();
    }

    @Test
    void convertToString_test() {
        Map<String, ExtensionClientInput> clientInputs = new HashMap<>();
        clientInputs.put(FIDOAppIDExtensionClientInput.ID, new FIDOAppIDExtensionClientInput("test"));
        assertThat(authenticationExtensionsClientInputsConverter.convertToString(new AuthenticationExtensionsClientInputs<>(clientInputs))).isEqualTo("{\"appid\":\"test\"}");
    }

    @Test
    void convertToString_null_test() {
        assertThat(authenticationExtensionsClientInputsConverter.convertToString(null)).isNull();
    }

    @Test
    void convert_test() {
        String source = "{\"appid\":\"dummy\"}";
        AuthenticationExtensionsClientInputs clientInputs = authenticationExtensionsClientInputsConverter.convert(source);
        assertThat(clientInputs.get(FIDOAppIDExtensionClientInput.ID)).isEqualTo(new FIDOAppIDExtensionClientInput("dummy"));
    }

    @Test
    void convert_with_invalid_extension_test() {
        String source = "{\"invalid\":\"\"}";
        assertThrows(DataConversionException.class,
                () -> authenticationExtensionsClientInputsConverter.convert(source)
        );
    }
}
