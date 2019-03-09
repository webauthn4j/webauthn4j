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

import com.webauthn4j.request.AuthenticatorTransport;
import com.webauthn4j.response.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.response.attestation.statement.AttestationStatement;
import com.webauthn4j.util.ConstUtil;

import java.util.Collections;
import java.util.Objects;
import java.util.Set;

/**
 * An {@link Authenticator} implementation
 */
public class AuthenticatorImpl implements Authenticator {

    //~ Instance fields ================================================================================================
    private AttestedCredentialData attestedCredentialData;
    private AttestationStatement attestationStatement;
    private Set<AuthenticatorTransport> transports;
    private long counter;

    public AuthenticatorImpl(AttestedCredentialData attestedCredentialData, AttestationStatement attestationStatement, long counter, Set<AuthenticatorTransport> transports) {
        this.attestedCredentialData = attestedCredentialData;
        this.attestationStatement = attestationStatement;
        this.transports = Collections.unmodifiableSet(transports);
        setCounter(counter);
    }

    public AuthenticatorImpl(AttestedCredentialData attestedCredentialData, AttestationStatement attestationStatement, long counter) {
        this(attestedCredentialData, attestationStatement, counter, Collections.emptySet());
    }

    @Override
    public AttestedCredentialData getAttestedCredentialData() {
        return attestedCredentialData;
    }

    public void setAttestedCredentialData(AttestedCredentialData attestedCredentialData) {
        this.attestedCredentialData = attestedCredentialData;
    }

    @Override
    public AttestationStatement getAttestationStatement() {
        return attestationStatement;
    }

    public void setAttestationStatement(AttestationStatement attestationStatement) {
        this.attestationStatement = attestationStatement;
    }

    @Override
    public long getCounter() {
        return this.counter;
    }

    @Override
    public void setCounter(long value) {
        if (value > ConstUtil.UINT_MAX_VALUE) {
            throw new IllegalArgumentException("[Assertion failed] - this argument is unsigned int. it must not exceed 4294967295.");
        }
        if (value < 0) {
            throw new IllegalArgumentException("[Assertion failed] - this argument is unsigned int. it must not be negative value.");
        }
        this.counter = value;
    }

    @Override
    public Set<AuthenticatorTransport> getTransports() {
        return transports;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuthenticatorImpl that = (AuthenticatorImpl) o;
        return counter == that.counter &&
                Objects.equals(attestedCredentialData, that.attestedCredentialData) &&
                Objects.equals(attestationStatement, that.attestationStatement) &&
                Objects.equals(transports, that.transports);
    }

    @Override
    public int hashCode() {

        return Objects.hash(attestedCredentialData, attestationStatement, transports, counter);
    }
}
