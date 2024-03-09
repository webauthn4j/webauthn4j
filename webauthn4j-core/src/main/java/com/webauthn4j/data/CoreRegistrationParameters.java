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

import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.server.CoreServerProperty;
import com.webauthn4j.util.AssertUtil;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.List;
import java.util.Objects;

public class CoreRegistrationParameters {

    // server property
    private final CoreServerProperty serverProperty;
    private final List<PublicKeyCredentialParameters> pubKeyCredParams;

    // verification condition
    private final boolean userVerificationRequired;
    private final boolean userPresenceRequired;

    /**
     * {@link CoreRegistrationParameters} constructor
     * @param serverProperty server property
     * @param pubKeyCredParams allowed {@link PublicKeyCredentialParameters}. If all {@link COSEAlgorithmIdentifier} are allowed, pass null
     * @param userVerificationRequired true if user verification is required. Otherwise, false
     * @param userPresenceRequired true if user presence is required. Otherwise, false
     */
    public CoreRegistrationParameters(@NonNull CoreServerProperty serverProperty,
                                      @Nullable List<PublicKeyCredentialParameters> pubKeyCredParams,
                                      boolean userVerificationRequired, boolean userPresenceRequired) {
        AssertUtil.notNull(serverProperty, "serverProperty must not be null");
        this.serverProperty = serverProperty;
        this.pubKeyCredParams = pubKeyCredParams;
        this.userVerificationRequired = userVerificationRequired;
        this.userPresenceRequired = userPresenceRequired;
    }

    /**
     * {@link CoreRegistrationParameters} constructor
     * @param serverProperty server property
     * @param pubKeyCredParams allowed {@link PublicKeyCredentialParameters}. If all {@link COSEAlgorithmIdentifier} are allowed, pass null
     * @param userVerificationRequired true if user verification is required. Otherwise, false
     */
    public CoreRegistrationParameters(@NonNull CoreServerProperty serverProperty,
                                      @Nullable List<PublicKeyCredentialParameters> pubKeyCredParams,
                                      boolean userVerificationRequired) {
        this(serverProperty, pubKeyCredParams, userVerificationRequired, true);
    }

    /**
     * @deprecated Deprecated as pubKeyCredParams verification was introduced from WebAuthn Level2.
     */
    @SuppressWarnings("squid:S1133")
    @Deprecated
    public CoreRegistrationParameters(@NonNull CoreServerProperty serverProperty,
                                      boolean userVerificationRequired, boolean userPresenceRequired) {
        this(serverProperty, null ,userVerificationRequired, userPresenceRequired);
    }

    /**
     * @deprecated Deprecated as pubKeyCredParams verification was introduced from WebAuthn Level2.
     */
    @SuppressWarnings("squid:S1133")
    @Deprecated
    public CoreRegistrationParameters(@NonNull CoreServerProperty serverProperty,
                                      boolean userVerificationRequired) {
        this(serverProperty, null, userVerificationRequired, true);
    }

    public @NonNull CoreServerProperty getServerProperty() {
        return serverProperty;
    }

    public @Nullable List<PublicKeyCredentialParameters> getPubKeyCredParams() {
        return pubKeyCredParams;
    }

    public boolean isUserVerificationRequired() {
        return userVerificationRequired;
    }

    public boolean isUserPresenceRequired() {
        return userPresenceRequired;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CoreRegistrationParameters that = (CoreRegistrationParameters) o;
        return userVerificationRequired == that.userVerificationRequired &&
                userPresenceRequired == that.userPresenceRequired &&
                Objects.equals(serverProperty, that.serverProperty) &&
                Objects.equals(pubKeyCredParams, that.pubKeyCredParams);
    }

    @Override
    public int hashCode() {
        return Objects.hash(serverProperty, pubKeyCredParams, userVerificationRequired, userPresenceRequired);
    }

    @Override
    public String toString() {
        return "CoreRegistrationParameters(" +
                "serverProperty=" + serverProperty +
                ", pubKeyCredParams=" + pubKeyCredParams +
                ", userVerificationRequired=" + userVerificationRequired +
                ", userPresenceRequired=" + userPresenceRequired +
                ')';
    }
}
