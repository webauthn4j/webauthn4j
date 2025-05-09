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
import com.webauthn4j.data.extension.HMACGetSecretInput;
import com.webauthn4j.data.extension.client.*;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SuppressWarnings("ConstantConditions")
class AuthenticationExtensionsClientInputsConverterTest {

    private final ObjectConverter objectConverter = new ObjectConverter();

    private final AuthenticationExtensionsClientInputsConverter target = new AuthenticationExtensionsClientInputsConverter(objectConverter);


    @SuppressWarnings("ConstantConditions")
    @Test
    void shouldThrowExceptionWhenConvertingNullRegistrationExtensions() {
        // Given
        // No setup needed
        
        // When/Then
        assertThatThrownBy(() -> target.convert(null)).isInstanceOf(DataConversionException.class);
    }

    @Test
    void shouldConvertAuthenticationExtensionsToJsonString() {
        // Given
        AuthenticationExtensionsClientInputs.BuilderForAuthentication builder = new AuthenticationExtensionsClientInputs.BuilderForAuthentication();
        builder.setAppid("test");
        AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput> extensions = builder.build();
        
        // When
        String result = target.convertToString(extensions);
        
        // Then
        assertThat(result).isEqualTo("{\"appid\":\"test\"}");
    }

    @SuppressWarnings("ConstantConditions")
    @Test
    void shouldThrowExceptionWhenConvertingNullExtensionsToString() {
        // Given
        // No setup needed
        
        // When/Then
        assertThatThrownBy(() -> target.convertToString(null)).isInstanceOf(DataConversionException.class);
    }

    @Test
    void shouldConvertJsonStringToAuthenticationExtensionsClientInputs() {
        // Given
        String source = "{\"appid\":\"testappid\",\"appidExclude\":\"testappidexclude\",\"uvm\":true,\"hmacGetSecret\":{\"salt1\":\"AA\",\"salt2\":\"AQ\"},\"myextension\":\"test\"}";
        
        // When
        AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput> clientInputs = target.convert(source);
        
        // Then
        assertThat(clientInputs.getExtension(FIDOAppIDExtensionClientInput.class)).isEqualTo(new FIDOAppIDExtensionClientInput("testappid"));
        assertThat(clientInputs.getExtension(FIDOAppIDExclusionExtensionClientInput.class)).isEqualTo(new FIDOAppIDExclusionExtensionClientInput("testappidexclude"));
        assertThat(clientInputs.getExtension(UserVerificationMethodExtensionClientInput.class)).isEqualTo(new UserVerificationMethodExtensionClientInput(true));
        assertThat(clientInputs.getExtension(HMACSecretAuthenticationExtensionClientInput.class)).isEqualTo(new HMACSecretAuthenticationExtensionClientInput(new HMACGetSecretInput(new byte[] {0}, new byte[] {1})));
        assertThat(clientInputs.getValue("myextension")).isEqualTo("test");
    }

    @Test
    void shouldReturnNullWhenConvertingNullJsonString() {
        // Given
        String source = "null";
        
        // When
        AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput> clientInputs = target.convert(source);
        
        // Then
        assertThat(clientInputs).isNull();
    }

    @SuppressWarnings("unused")
    @Test
    void shouldHandleInvalidExtensionsInJsonString() {
        // Given
        String source = "{\"invalid\":\"\"}";
        
        // When
        AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> extensions = target.convert(source);
        
        // Then
        assertThat(extensions.getUnknownKeys()).contains("invalid");
    }
}
