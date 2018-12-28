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

package com.webauthn4j.authenticator;

import com.webauthn4j.response.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.response.attestation.statement.AttestationStatement;
import com.webauthn4j.test.TestUtil;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class AuthenticatorImplTest {

    @Test
    public void getter_setter_test() {

        AttestedCredentialData attestedCredentialData = TestUtil.createAttestedCredentialData();
        AttestationStatement attestationStatement = TestUtil.createFIDOU2FAttestationStatement();
        Authenticator authenticator = TestUtil.createAuthenticator(attestedCredentialData, attestationStatement);

        assertThat(authenticator.getAttestedCredentialData()).isEqualTo(attestedCredentialData);
        assertThat(authenticator.getAttestationStatement()).isEqualTo(attestationStatement);
        assertThat(authenticator.getCounter()).isEqualTo(1);

    }

    @Test
    public void setCounter_range_test() {
        AuthenticatorImpl authenticator = new AuthenticatorImpl();
        assertThatThrownBy(() -> authenticator.setCounter(-1)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> authenticator.setCounter(4294967296L)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    public void equals_hashCode_test(){
        Authenticator authenticatorA = TestUtil.createAuthenticator();
        Authenticator authenticatorB = TestUtil.createAuthenticator();

        assertThat(authenticatorA).isEqualTo(authenticatorB);
        assertThat(authenticatorA).hasSameHashCodeAs(authenticatorB);
    }
}
