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

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientInput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.data.extension.client.FIDOAppIDExtensionClientInput;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientInput;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AuthenticationExtensionsClientInputsConverterTest {

    private final ObjectConverter objectConverter = new ObjectConverter();

    private final AuthenticationExtensionsClientInputsConverter authenticationExtensionsClientInputsConverter = new AuthenticationExtensionsClientInputsConverter(objectConverter);


    @Test
    void convertRegistrationExtensions_null_test() {
        AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> value = authenticationExtensionsClientInputsConverter.convert(null);
        assertThat(value).isNull();
    }

    @Test
    void convertAuthenticationExtensionsToString_test() {
        AuthenticationExtensionsClientInputs.BuilderForAuthentication builder = new AuthenticationExtensionsClientInputs.BuilderForAuthentication();
        builder.setAppid("test");
        AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput> extensions = builder.build();
        assertThat(authenticationExtensionsClientInputsConverter.convertToString(extensions)).isEqualTo("{\"appid\":\"test\"}");
    }

    @Test
    void convertAuthenticationExtensionsToString_null_test() {
        assertThat(authenticationExtensionsClientInputsConverter.convertToString(null)).isNull();
    }

    @Test
    void convert_test() {
        String source = "{\"appid\":\"dummy\"}";
        AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput> clientInputs = authenticationExtensionsClientInputsConverter.convert(source);
        assertThat(clientInputs.getExtension(FIDOAppIDExtensionClientInput.class)).isEqualTo(new FIDOAppIDExtensionClientInput("dummy"));
    }

    @SuppressWarnings("unused")
    @Test
    void convert_with_invalid_extension_test() {
        String source = "{\"invalid\":\"\"}";
        AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> extensions = authenticationExtensionsClientInputsConverter.convert(source);
        assertThat(extensions.getUnknownKeys()).contains("invalid");

    }
}
