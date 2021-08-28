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

package com.webauthn4j.data;

import com.webauthn4j.util.ArrayUtil;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.util.CollectionUtil;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.Arrays;
import java.util.Collections;
import java.util.Objects;
import java.util.Set;

/**
 * The {@link AuthenticatorAttestationResponse} represents the authenticator's response to a client’s request
 * for the creation of a new public key credential.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-1/#authenticatorattestationresponse">§5.2.1. Information About Public Key Credential (interface AuthenticatorAttestationResponse)</a>
 */
public class AuthenticatorAttestationResponse extends AuthenticatorResponse {

    // ~ Instance fields
    // ================================================================================================

    private final byte[] attestationObject;
    private final Set<AuthenticatorTransport> transports;

    // ~ Constructor
    // ========================================================================================================

    public AuthenticatorAttestationResponse(@NonNull byte[] clientDataJSON,
                                            @NonNull byte[] attestationObject) {
        this(clientDataJSON, attestationObject, Collections.emptySet());
    }

    public AuthenticatorAttestationResponse(@NonNull byte[] clientDataJSON,
                                            @NonNull byte[] attestationObject,
                                            @Nullable Set<AuthenticatorTransport> transports) {
        super(clientDataJSON);
        AssertUtil.notNull(attestationObject, "attestationObject must not be null");


        this.attestationObject = attestationObject;
        this.transports = CollectionUtil.unmodifiableSet(transports);
    }


    /**
     * Returns an attestation object, which is opaque to, and cryptographically protected against tampering by, the client.
     *
     * @return byte array representation of {@link com.webauthn4j.data.attestation.AttestationObject}
     */
    public @NonNull byte[] getAttestationObject() {
        return ArrayUtil.clone(attestationObject);
    }

    /**
     * Returns a sequence of zero or more unique {@link AuthenticatorTransport} values in lexicographical order.
     * These values are the transports that the authenticator is believed to support, or an empty sequence
     * if the information is unavailable.
     *
     * @return list of {@link AuthenticatorTransport}
     */
    public @NonNull Set<AuthenticatorTransport> getTransports() {
        return this.transports;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuthenticatorAttestationResponse that = (AuthenticatorAttestationResponse) o;
        return Arrays.equals(attestationObject, that.attestationObject) &&
                Objects.equals(transports, that.transports);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int hashCode() {

        int result = Objects.hash(transports);
        result = 31 * result + Arrays.hashCode(attestationObject);
        return result;
    }

    @Override
    public String toString() {
        return "AuthenticatorAttestationResponse(" +
                "attestationObject=" + ArrayUtil.toHexString(attestationObject) +
                ", transports=" + transports +
                ')';
    }
}
