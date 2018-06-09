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

import com.webauthn4j.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.extension.authneticator.AuthenticatorExtensionOutput;
import com.webauthn4j.extension.authneticator.SupportedExtensionsAuthenticatorExtensionOutput;
import com.webauthn4j.util.Base64UrlUtil;
import org.junit.Test;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.webauthn4j.attestation.authenticator.AuthenticatorData.BIT_ED;
import static com.webauthn4j.attestation.authenticator.AuthenticatorData.BIT_UP;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test for AuthenticatorDataConverter
 */
public class AuthenticatorDataConverterTest {

    @Test
    public void convert_test() {
        //Given
        String input = "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAABRTBGAiEA77SC7T44f9E6NEEwiHBkcI3jSL70jAcvEN3lDJoFpxUCIQDxuc-Oq1UgYUxftfXu4wbsDQiTz_6cJJfe00d5t6nrNw==";

        //When
        AuthenticatorData result = new AuthenticatorDataConverter().convert(Base64UrlUtil.decode(input));

        //Then
        assertThat(result.getRpIdHash()).isNotNull();
        assertThat(result.getRpIdHash()).hasSize(32);
        assertThat(result.getFlags()).isEqualTo(BIT_UP);
        assertThat(result.getSignCount()).isEqualTo(325);
        assertThat(result.getAttestedCredentialData()).isNull();
        assertThat(result.getExtensions()).isEmpty();
    }

    @Test
    public void serialize_deserialize_test() {
        //Given
        byte[] rpIdHash = new byte[32];
        byte flags = BIT_ED;
        Map<String, AuthenticatorExtensionOutput> extensionOutputMap = new HashMap<>();
        List<String> extension = Collections.singletonList("uvm");
        SupportedExtensionsAuthenticatorExtensionOutput extensionOutput = new SupportedExtensionsAuthenticatorExtensionOutput(extension);
        extensionOutputMap.put(extensionOutput.getIdentifier(), extensionOutput);
        AuthenticatorData authenticatorData = new AuthenticatorData(rpIdHash, flags, 0, extensionOutputMap);

        //When
        byte[] serialized = new AuthenticatorDataConverter().convert(authenticatorData);
        AuthenticatorData result = new AuthenticatorDataConverter().convert(serialized);

        //Then
        assertThat(result.getRpIdHash()).isNotNull();
        assertThat(result.getRpIdHash()).hasSize(32);
        assertThat(result.getFlags()).isEqualTo(BIT_ED);
        assertThat(result.getSignCount()).isEqualTo(0);
        assertThat(result.getAttestedCredentialData()).isNull();
        assertThat(result.getExtensions()).containsKeys(SupportedExtensionsAuthenticatorExtensionOutput.ID);
        assertThat(result.getExtensions()).containsValues(extensionOutput);
    }
}
