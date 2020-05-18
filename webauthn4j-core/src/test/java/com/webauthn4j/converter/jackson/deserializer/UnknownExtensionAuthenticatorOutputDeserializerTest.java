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

import com.fasterxml.jackson.core.type.TypeReference;
import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.data.extension.authenticator.ExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.authenticator.UnknownExtensionAuthenticatorOutput;
import com.webauthn4j.util.HexUtil;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

class UnknownExtensionAuthenticatorOutputDeserializerTest {

    private ObjectConverter objectConverter = new ObjectConverter();
    private CborConverter cborConverter = objectConverter.getCborConverter();

    @Test
    void test() {


        //Given
        byte[] input = HexUtil.decode("A16A756E6578706563746564F5"); // {"unexpected": true}

        //When
        AuthenticationExtensionsAuthenticatorOutputs<ExtensionAuthenticatorOutput<?>> result = cborConverter.readValue(input, new TypeReference<AuthenticationExtensionsAuthenticatorOutputs<ExtensionAuthenticatorOutput<?>>>() {});

        //Then
        assertAll(
                ()-> assertThat(result.get("unexpected")).isInstanceOf(UnknownExtensionAuthenticatorOutput.class),
                ()-> assertThat(result.get("unexpected").getIdentifier()).isEqualTo("unexpected"),
                ()-> assertThat(((UnknownExtensionAuthenticatorOutput)result.get("unexpected")).getValue()).isEqualTo(true)
        );
    }
}
