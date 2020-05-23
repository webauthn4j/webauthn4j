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

package com.webauthn4j.authenticator;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
import com.webauthn4j.test.TestAttestationStatementUtil;
import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.util.CollectionUtil;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class AuthenticatorTest {

    @Test
    void serialization_deserialization_test() {
        ObjectConverter objectConverter = new ObjectConverter();
        CborConverter cborConverter = objectConverter.getCborConverter();

        TestAuthenticator original = new TestAuthenticator(
                TestDataUtil.createAttestedCredentialData(),
                TestAttestationStatementUtil.createFIDOU2FAttestationStatement(),
                0,
                Collections.emptySet(),
                null,
                null);
        byte[] serialized = cborConverter.writeValueAsBytes(original);
        Authenticator deserialized = cborConverter.readValue(serialized, TestAuthenticator.class);

        assertThat(deserialized).isEqualTo(original);
    }

    private static class TestAuthenticator implements Authenticator {

        private final AttestedCredentialData attestedCredentialData;
        private final AttestationStatement attestationStatement;
        private final Set<AuthenticatorTransport> transports;
        private long counter;

        private final Map<String, RegistrationExtensionClientOutput<?>> clientExtensions;
        private final Map<String, RegistrationExtensionAuthenticatorOutput<?>> authenticatorExtensions;

        public TestAuthenticator(
                @JsonProperty("attestedCredentialData") AttestedCredentialData attestedCredentialData,
                @JsonProperty("attestationStatement") AttestationStatement attestationStatement,
                @JsonProperty("counter") long counter,
                @JsonProperty("transports") Set<AuthenticatorTransport> transports,
                @JsonProperty("clientExtensions") Map<String, RegistrationExtensionClientOutput<?>> clientExtensions,
                @JsonProperty("authenticatorExtensions") Map<String, RegistrationExtensionAuthenticatorOutput<?>> authenticatorExtensions) {
            this.attestedCredentialData = attestedCredentialData;
            this.attestationStatement = attestationStatement;
            this.transports = CollectionUtil.unmodifiableSet(transports);
            this.clientExtensions = clientExtensions;
            this.authenticatorExtensions = authenticatorExtensions;
            setCounter(counter);
        }

        @Override
        public AttestedCredentialData getAttestedCredentialData() {
            return attestedCredentialData;
        }

        @JsonTypeInfo(
                use = JsonTypeInfo.Id.NAME,
                include = JsonTypeInfo.As.EXTERNAL_PROPERTY,
                property = "format"
        )
        @Override
        public AttestationStatement getAttestationStatement() {
            return attestationStatement;
        }

        @JsonProperty("format")
        public String getFormat() {
            return attestationStatement.getFormat();
        }

        @Override
        public Set<AuthenticatorTransport> getTransports() {
            return transports;
        }

        @Override
        public long getCounter() {
            return counter;
        }

        @Override
        public void setCounter(long counter) {
            this.counter = counter;
        }

        @Override
        public Map<String, RegistrationExtensionClientOutput<?>> getClientExtensions() {
            return clientExtensions;
        }

        @Override
        public Map<String, RegistrationExtensionAuthenticatorOutput<?>> getAuthenticatorExtensions() {
            return authenticatorExtensions;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            TestAuthenticator that = (TestAuthenticator) o;
            return counter == that.counter &&
                    Objects.equals(attestedCredentialData, that.attestedCredentialData) &&
                    Objects.equals(attestationStatement, that.attestationStatement) &&
                    Objects.equals(transports, that.transports) &&
                    Objects.equals(clientExtensions, that.clientExtensions) &&
                    Objects.equals(authenticatorExtensions, that.authenticatorExtensions);
        }

        @Override
        public int hashCode() {
            return Objects.hash(attestedCredentialData, attestationStatement, transports, counter, clientExtensions, authenticatorExtensions);
        }
    }

}
