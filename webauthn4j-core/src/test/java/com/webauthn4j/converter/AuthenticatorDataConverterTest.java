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

package com.webauthn4j.converter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.response.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.response.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.response.extension.authenticator.ExtensionAuthenticatorOutput;
import com.webauthn4j.response.extension.authenticator.SupportedExtensionsExtensionAuthenticatorOutput;
import com.webauthn4j.util.Base64UrlUtil;
import org.junit.Test;

import java.util.*;

import static com.webauthn4j.response.attestation.authenticator.AuthenticatorData.BIT_ED;
import static com.webauthn4j.response.attestation.authenticator.AuthenticatorData.BIT_UP;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test for AuthenticatorDataConverter
 */
public class AuthenticatorDataConverterTest {

    private ObjectMapper objectMapper = new ObjectMapper();

    @Test
    public void convert_test() {
        //Given
        //noinspection SpellCheckingInspection
        String input = "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAABRQ";

        //When
        AuthenticatorData result = new AuthenticatorDataConverter(objectMapper).convert(Base64UrlUtil.decode(input));

        //Then
        assertThat(result.getRpIdHash()).isNotNull();
        assertThat(result.getRpIdHash()).hasSize(32);
        assertThat(result.getFlags()).isEqualTo(BIT_UP);
        assertThat(result.getSignCount()).isEqualTo(325);
        assertThat(result.getAttestedCredentialData()).isNull();
        assertThat(result.getExtensions()).isEmpty();
    }

    @Test(expected = DataConversionException.class)
    public void convert_too_short_data_test() {
        //Given
        //noinspection SpellCheckingInspection
        String input = "SZYN5YgOjGh0NBcP";

        //When
        new AuthenticatorDataConverter(objectMapper).convert(Base64UrlUtil.decode(input));
    }

    @Test
    public void serialize_deserialize_test() {
        //Given
        byte[] rpIdHash = new byte[32];
        byte flags = BIT_ED;
        Map<String, ExtensionAuthenticatorOutput> extensionOutputMap = new HashMap<>();
        List<String> extension = Collections.singletonList("uvm");
        SupportedExtensionsExtensionAuthenticatorOutput extensionOutput = new SupportedExtensionsExtensionAuthenticatorOutput(extension);
        extensionOutputMap.put(extensionOutput.getIdentifier(), extensionOutput);
        AuthenticatorData authenticatorData = new AuthenticatorData(rpIdHash, flags, 0, new AuthenticationExtensionsAuthenticatorOutputs<>(extensionOutputMap));

        //When
        byte[] serialized = new AuthenticatorDataConverter(objectMapper).convert(authenticatorData);
        AuthenticatorData result = new AuthenticatorDataConverter(objectMapper).convert(serialized);

        //Then
        assertThat(result.getRpIdHash()).isNotNull();
        assertThat(result.getRpIdHash()).hasSize(32);
        assertThat(result.getFlags()).isEqualTo(BIT_ED);
        assertThat(result.getSignCount()).isEqualTo(0);
        assertThat(result.getAttestedCredentialData()).isNull();
        assertThat(result.getExtensions()).containsKeys(SupportedExtensionsExtensionAuthenticatorOutput.ID);
        assertThat(result.getExtensions()).containsValues(extensionOutput);
    }

    @Test(expected = DataConversionException.class)
    public void deserialize_data_with_surplus_bytes_test() {
        //noinspection SpellCheckingInspection
        String input = "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAABRQ";
        byte[] data = Base64UrlUtil.decode(input);
        byte[] bytes = Arrays.copyOf(data, data.length + 1);
        //When
        new AuthenticatorDataConverter(objectMapper).convert(bytes);
    }
}
