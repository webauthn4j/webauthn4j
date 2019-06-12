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

package com.webauthn4j;

import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.data.WebAuthnRegistrationContext;
import com.webauthn4j.data.client.ClientDataType;
import com.webauthn4j.server.ServerProperty;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.Set;

import static com.webauthn4j.test.TestDataUtil.createAttestationObjectWithFIDOU2FAttestationStatement;
import static com.webauthn4j.test.TestDataUtil.createClientData;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class WebAuthnRegistrationContextTest {

    private JsonConverter jsonConverter = new JsonConverter();
    private CborConverter cborConverter = CborConverter.INSTANCE;


    @Test
    void test() {
        byte[] collectedClientData = new CollectedClientDataConverter(jsonConverter).convertToBytes(createClientData(ClientDataType.GET));
        byte[] authenticatorData = new AttestationObjectConverter(cborConverter).convertToBytes(createAttestationObjectWithFIDOU2FAttestationStatement());
        Set<String> transports = Collections.emptySet();


        ServerProperty serverProperty = mock(ServerProperty.class);

        WebAuthnRegistrationContext webAuthnRegistrationContextA = new WebAuthnRegistrationContext(collectedClientData, authenticatorData, transports, serverProperty, false);
        WebAuthnRegistrationContext webAuthnRegistrationContextB = new WebAuthnRegistrationContext(collectedClientData, authenticatorData, transports, serverProperty, false);

        assertThat(webAuthnRegistrationContextA).isEqualTo(webAuthnRegistrationContextB);
        assertThat(webAuthnRegistrationContextA).hasSameHashCodeAs(webAuthnRegistrationContextB);
    }
}
