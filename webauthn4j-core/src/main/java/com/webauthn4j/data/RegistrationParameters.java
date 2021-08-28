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
import com.webauthn4j.server.ServerProperty;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.List;

public class RegistrationParameters extends CoreRegistrationParameters {

    /**
     * {@link RegistrationParameters} constructor
     * @param serverProperty server property
     * @param pubKeyCredParams allowed {@link PublicKeyCredentialParameters}. If all {@link COSEAlgorithmIdentifier} are allowed, pass null
     * @param userVerificationRequired true if user verification is required. Otherwise, false
     * @param userPresenceRequired true if user presence is required. Otherwise, false
     */
    public RegistrationParameters(@NonNull ServerProperty serverProperty, @Nullable List<PublicKeyCredentialParameters> pubKeyCredParams, boolean userVerificationRequired, boolean userPresenceRequired) {
        super(serverProperty, pubKeyCredParams, userVerificationRequired, userPresenceRequired);
    }

    /**
     * {@link RegistrationParameters} constructor
     * @param serverProperty server property
     * @param pubKeyCredParams allowed {@link PublicKeyCredentialParameters}. If all {@link COSEAlgorithmIdentifier} are allowed, pass null
     * @param userVerificationRequired true if user verification is required. Otherwise, false
     */
    public RegistrationParameters(@NonNull ServerProperty serverProperty, @Nullable List<PublicKeyCredentialParameters> pubKeyCredParams, boolean userVerificationRequired) {
        super(serverProperty, pubKeyCredParams, userVerificationRequired);
    }

    /**
     * @deprecated Deprecated as pubKeyCredParams verification was introduced from WebAuthn Level2.
     */
    @SuppressWarnings("squid:S1133")
    @Deprecated
    public RegistrationParameters(
            @NonNull ServerProperty serverProperty,
            boolean userVerificationRequired,
            boolean userPresenceRequired) {
        super(serverProperty, userVerificationRequired, userPresenceRequired);
    }

    /**
     * @deprecated Deprecated as pubKeyCredParams verification was introduced from WebAuthn Level2.
     */
    @SuppressWarnings("squid:S1133")
    @Deprecated
    public RegistrationParameters(
            @NonNull ServerProperty serverProperty,
            boolean userVerificationRequired) {
        super(serverProperty, userVerificationRequired);
    }

    @Override
    public @NonNull ServerProperty getServerProperty() {
        return (ServerProperty) super.getServerProperty();
    }
}
