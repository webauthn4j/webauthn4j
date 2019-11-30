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

package com.webauthn4j.validator.exception;

import com.webauthn4j.validator.RegistrationObject;

/**
 * Thrown if the public key in the first certificate in x5c doesn't matches the credentialPublicKey in the attestedCredentialData
 */
public class PublicKeyMismatchException extends ValidationException {
    public PublicKeyMismatchException(String message, Throwable cause) {
        super(message, cause);
    }

    public PublicKeyMismatchException(String message) {
        super(message);
    }

    public PublicKeyMismatchException(Throwable cause) {
        super(cause);
    }

    public PublicKeyMismatchException(String message, RegistrationObject registrationObject, Throwable cause) {
        super(message, registrationObject, cause);
    }

    public PublicKeyMismatchException(String message, RegistrationObject registrationObject) {
        super(message, registrationObject);
    }

    public PublicKeyMismatchException(RegistrationObject registrationObject, Throwable cause) {
        super(registrationObject, cause);
    }
}
