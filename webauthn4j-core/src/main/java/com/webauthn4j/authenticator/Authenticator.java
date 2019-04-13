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

import java.io.Serializable;
import java.util.Set;

/**
 * Core interface that represents WebAuthn authenticator
 */
public interface Authenticator extends Serializable {

    /**
     * Returns the {@link AttestedCredentialData}
     * @return the {@link AttestedCredentialData}
     */
    AttestedCredentialData getAttestedCredentialData();

    /**
     * Returns the {@link AttestationStatement}
     * @return the {@link AttestationStatement}
     */
    AttestationStatement getAttestationStatement();

    /**
     * Returns the {@link AuthenticatorTransport} {@link Set}
     * @return the {@link AuthenticatorTransport} {@link Set}
     */
    Set<AuthenticatorTransport> getTransports();

    /**
     * Returns the counter value
     * @return the counter value
     */
    long getCounter();

    /**
     * Sets the counter value
     * @param value the counter value
     */
    void setCounter(long value);

}
