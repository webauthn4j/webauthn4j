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
import com.webauthn4j.data.extension.HMACGetSecretOutput;
import com.webauthn4j.data.extension.UvmEntries;
import com.webauthn4j.data.extension.client.*;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AuthenticationExtensionsClientOutputsConverterTest {

    private final ObjectConverter objectConverter = new ObjectConverter();

    private final AuthenticationExtensionsClientOutputsConverter target = new AuthenticationExtensionsClientOutputsConverter(objectConverter);

    @Test
    void convert_null_test() {
        //noinspection ConstantConditions
        assertThatThrownBy(() -> target.convert(null)).isInstanceOf(DataConversionException.class);
    }

    @Test
    void convertToString_null_test() {
        //noinspection ConstantConditions
        assertThatThrownBy(() -> target.convertToString(null)).isInstanceOf(DataConversionException.class);
    }

    @Test
    void convert_test() {
        String source = "{\"appid\":true,\"uvm\":[],\"hmacGetSecret\":{\"output1\":\"AA\",\"output2\":\"AQ\"},\"myextension\":\"test\"}"; // "appidExclude":"testappidexclude"
        AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput> clientOutputs = target.convert(source);
        assertThat(clientOutputs.getExtension(UserVerificationMethodExtensionClientOutput.class)).isEqualTo(new UserVerificationMethodExtensionClientOutput(new UvmEntries()));
        assertThat(clientOutputs.getExtension(HMACSecretAuthenticationExtensionClientOutput.class)).isEqualTo(new HMACSecretAuthenticationExtensionClientOutput(new HMACGetSecretOutput(new byte[] {0}, new byte[] {1})));
        assertThat(clientOutputs.getValue("myextension")).isEqualTo("test");
    }

}