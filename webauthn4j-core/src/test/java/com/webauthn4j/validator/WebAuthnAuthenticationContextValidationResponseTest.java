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

package com.webauthn4j.validator;

import com.webauthn4j.registry.Registry;
import com.webauthn4j.response.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.response.client.ClientDataType;
import com.webauthn4j.response.client.CollectedClientData;
import com.webauthn4j.response.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.test.TestUtil;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class WebAuthnAuthenticationContextValidationResponseTest {

    @Test
    public void equals_hashCode_test(){
        Registry registry = new Registry();
        CollectedClientData clientData = TestUtil.createClientData(ClientDataType.CREATE);
        AuthenticatorData authenticatorData = TestUtil.createAuthenticatorData();
        AuthenticationExtensionsClientOutputs authenticationExtensionsClientOutputs = new AuthenticationExtensionsClientOutputs();
        WebAuthnAuthenticationContextValidationResponse instanceA =
                new WebAuthnAuthenticationContextValidationResponse(clientData, authenticatorData, authenticationExtensionsClientOutputs);
        WebAuthnAuthenticationContextValidationResponse instanceB =
                new WebAuthnAuthenticationContextValidationResponse(clientData, authenticatorData, authenticationExtensionsClientOutputs);
        assertThat(instanceA).isEqualTo(instanceB);
        assertThat(instanceA).hasSameHashCodeAs(instanceB);
    }
}
