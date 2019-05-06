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

import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.test.TestAttestationStatementUtil;
import com.webauthn4j.test.TestDataUtil;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AuthenticatorImplTest {

    @Test
    void constructor_test() {
        AttestedCredentialData attestedCredentialData = TestDataUtil.createAttestedCredentialData();
        AttestationStatement attestationStatement = TestAttestationStatementUtil.createFIDOU2FAttestationStatement();
        Authenticator authenticator = TestDataUtil.createAuthenticator(attestedCredentialData, attestationStatement);

        assertAll(
                () -> assertThat(authenticator.getAttestedCredentialData()).isEqualTo(attestedCredentialData),
                () -> assertThat(authenticator.getAttestationStatement()).isEqualTo(attestationStatement),
                () -> assertThat(authenticator.getCounter()).isEqualTo(1)
        );
    }

    @Test
    void getter_setter_test() {
        AttestedCredentialData attestedCredentialData = TestDataUtil.createAttestedCredentialData();
        AttestationStatement attestationStatement = TestAttestationStatementUtil.createFIDOU2FAttestationStatement();
        AuthenticatorImpl authenticator = new AuthenticatorImpl(null, null, 0);
        Set<AuthenticatorTransport> transports = Collections.singleton(AuthenticatorTransport.USB);
        authenticator.setAttestedCredentialData(attestedCredentialData);
        authenticator.setAttestationStatement(attestationStatement);
        authenticator.setTransports(transports);
        authenticator.setCounter(1);

        assertAll(
                () -> assertThat(authenticator.getAttestedCredentialData()).isEqualTo(attestedCredentialData),
                () -> assertThat(authenticator.getAttestationStatement()).isEqualTo(attestationStatement),
                () -> assertThat(authenticator.getTransports()).isEqualTo(transports),
                () -> assertThat(authenticator.getCounter()).isEqualTo(1)
        );
    }

    @Test
    void setCounter_range_test() {
        AuthenticatorImpl authenticator = new AuthenticatorImpl(null, null, 0);

        assertAll(
                () -> assertThrows(IllegalArgumentException.class,
                        () -> authenticator.setCounter(-1)
                ),
                () -> assertThrows(IllegalArgumentException.class,
                        () -> authenticator.setCounter(4294967296L)
                )
        );
    }

    @Test
    void equals_hashCode_test() {
        Authenticator authenticatorA = TestDataUtil.createAuthenticator();
        Authenticator authenticatorB = TestDataUtil.createAuthenticator();

        assertAll(
                () -> assertThat(authenticatorA).isEqualTo(authenticatorB),
                () -> assertThat(authenticatorA).hasSameHashCodeAs(authenticatorB)
        );
    }
}
