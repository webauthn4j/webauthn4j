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

package com.webauthn4j.verifier.internal;

import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.verifier.exception.UserNotPresentException;
import com.webauthn4j.verifier.exception.UserNotVerifiedException;

/**
 * Verifies the UP (User Present) and UV (User Verified) flags in authenticator data.
 * <p>
 * Implements verification steps defined in:
 * <a href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">
 * WebAuthn Level 3 § 7.2 Verifying an Authentication Assertion</a>
 *
 * @see <a href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">WebAuthn Level 3 § 7.2</a>
 */
public class UPUVFlagsVerifier {

    private UPUVFlagsVerifier(){}

    /**
     * Verifies the UP and UV flags according to WebAuthn Level 3 specification.
     *
     * @param authenticatorData the authenticator data containing flags
     * @param isUserPresenceRequired whether user presence verification is required
     * @param isUserVerificationRequired whether user verification is required
     * @throws UserNotPresentException if UP flag is not set when required
     * @throws UserNotVerifiedException if UV flag is not set when required
     */
    public static void verify(AuthenticatorData<?> authenticatorData, boolean isUserPresenceRequired, boolean isUserVerificationRequired) {
        // Verify that the UP bit of the flags in authData is set (if required by configuration).
        if (isUserPresenceRequired && !authenticatorData.isFlagUP()) {
            throw new UserNotPresentException("Verifier is configured to check user present, but UP flag in authenticatorData is not set.");
        }

        // Determine whether user verification is required for this operation.
        // If user verification is required, verify that the UV bit of the flags in authData is set.
        if (isUserVerificationRequired && !authenticatorData.isFlagUV()) {
            throw new UserNotVerifiedException("Verifier is configured to check user verified, but UV flag in authenticatorData is not set.");
        }
    }
}
