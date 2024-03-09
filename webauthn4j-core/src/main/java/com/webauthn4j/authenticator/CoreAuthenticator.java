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

import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;


/**
 * Core interface that represents WebAuthn authenticator
 */
public interface CoreAuthenticator {

    /**
     * Returns the {@link AttestedCredentialData}
     *
     * @return the {@link AttestedCredentialData}
     */
    @NonNull AttestedCredentialData getAttestedCredentialData();

    /**
     * Returns the {@link AttestationStatement}
     *
     * @return the {@link AttestationStatement}
     */
    default @Nullable AttestationStatement getAttestationStatement() {
        return null;
    }

    /**
     * Returns the counter value
     *
     * @return the counter value
     */
    long getCounter();

    /**
     * Sets the counter value
     *
     * @param value the counter value
     */
    void setCounter(long value);

    /**
     * Returns the authenticator extensions
     *
     * @return the authenticator extensions
     */
    default @Nullable AuthenticationExtensionsAuthenticatorOutputs<RegistrationExtensionAuthenticatorOutput> getAuthenticatorExtensions() {
        return null;
    }

}
