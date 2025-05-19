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

package com.webauthn4j.verifier;

import com.webauthn4j.data.client.Origin;
import org.jetbrains.annotations.NotNull;

/**
 * Handler interface to verify the given {@link Origin} instance.
 * This verifier checks that the origin provided in the client data matches
 * the expected origin for the Relying Party during WebAuthn registration
 * and authentication ceremonies.
 */
public interface OriginVerifier {

    /**
     * Verifies the origin in the registration ceremony.
     *
     * @param registrationObject the object containing registration data to verify
     * @throws com.webauthn4j.verifier.exception.BadOriginException if the origin is invalid
     */
    void verify(@NotNull RegistrationObject registrationObject);

    /**
     * Verifies the origin in the authentication ceremony.
     *
     * @param authenticationObject the object containing authentication data to verify
     * @throws com.webauthn4j.verifier.exception.BadOriginException if the origin is invalid
     */
    void verify(@NotNull AuthenticationObject authenticationObject);
}
