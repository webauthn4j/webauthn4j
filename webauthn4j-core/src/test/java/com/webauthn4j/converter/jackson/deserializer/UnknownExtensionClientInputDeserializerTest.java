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

package com.webauthn4j.converter.jackson.deserializer;

import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.data.extension.client.UnknownExtensionClientInput;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

class UnknownExtensionClientInputDeserializerTest {

    private ObjectConverter objectConverter = new ObjectConverter();
    private JsonConverter jsonConverter = objectConverter.getJsonConverter();

    @Test
    void test() {


        //Given
        String input = "{\"unexpected\": true}";

        //When
        AuthenticationExtensionsClientInputs result = jsonConverter.readValue(input, AuthenticationExtensionsClientInputs.class);

        //Then
        assertAll(
                ()-> assertThat(result.get("unexpected")).isInstanceOf(UnknownExtensionClientInput.class),
                ()-> assertThat(((UnknownExtensionClientInput)result.get("unexpected")).getIdentifier()).isEqualTo("unexpected"),
                ()-> assertThat(((UnknownExtensionClientInput)result.get("unexpected")).getValue()).isEqualTo(true)
        );
    }

}