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

package com.webauthn4j.jackson.deserializer;

import com.webauthn4j.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.util.Base64UrlUtil;
import org.junit.Test;

import static com.webauthn4j.attestation.authenticator.AuthenticatorData.BIT_UP;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test for AuthenticatorDataDeserializer
 */
public class AuthenticatorDataDeserializerTest {

    @Test
    public void test() {
        //Given
        String input = "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAABRTBGAiEA77SC7T44f9E6NEEwiHBkcI3jSL70jAcvEN3lDJoFpxUCIQDxuc-Oq1UgYUxftfXu4wbsDQiTz_6cJJfe00d5t6nrNw==";

        //When
        AuthenticatorData result = new AuthenticatorDataDeserializer().deserialize(Base64UrlUtil.decode(input));

        //Then
        assertThat(result.getRpIdHash()).isNotNull();
        assertThat(result.getRpIdHash()).hasSize(32);
        assertThat(result.getFlags()).isEqualTo(BIT_UP);
        assertThat(result.getCounter()).isEqualTo(325);
        assertThat(result.getAttestedCredentialData()).isNull();
        assertThat(result.getExtensions()).isNull();
    }
}
