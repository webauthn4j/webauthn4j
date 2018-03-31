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

package com.webauthn4j.webauthn.converter;

import com.webauthn4j.test.CoreTestUtil;
import com.webauthn4j.webauthn.attestation.WebAuthnAttestationObject;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class WebAuthnAttestationObjectToBase64StringConverterTest {

    private WebAuthnAttestationObjectConverter target = new WebAuthnAttestationObjectConverter();

    @Test
    public void convert_test() {
        WebAuthnAttestationObject input = CoreTestUtil.createWebAuthnAttestationObjectWithFIDOU2FAttestationStatement();
        String result = target.convert(input);
        WebAuthnAttestationObject deserialized = target.convert(result);
        assertThat(deserialized).isEqualTo(input);
    }
}
