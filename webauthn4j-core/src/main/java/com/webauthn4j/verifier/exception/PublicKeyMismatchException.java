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

package com.webauthn4j.verifier.exception;

import org.jetbrains.annotations.Nullable;

/**
 * Thrown if the public key in the first certificate in x5c doesn't matches the credentialPublicKey in the attestedCredentialData
 */
@SuppressWarnings("squid:S110")
public class PublicKeyMismatchException extends VerificationException {
    public PublicKeyMismatchException(@Nullable String message, @Nullable Throwable cause) {
        super(message, cause);
    }

    public PublicKeyMismatchException(@Nullable String message) {
        super(message);
    }

    public PublicKeyMismatchException(@Nullable Throwable cause) {
        super(cause);
    }
}
