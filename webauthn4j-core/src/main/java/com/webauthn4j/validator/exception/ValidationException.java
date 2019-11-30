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

import com.webauthn4j.util.exception.WebAuthnException;
import com.webauthn4j.validator.AuthenticationObject;
import com.webauthn4j.validator.RegistrationObject;

/**
 * An abstract exception for validation violation
 */
public abstract class ValidationException extends WebAuthnException {

    private RegistrationObject registrationObject;
    private AuthenticationObject authenticationObject;

    public ValidationException(String message, Throwable cause) {
        super(message, cause);
    }

    public ValidationException(String message) {
        super(message);
    }

    public ValidationException(Throwable cause) {
        super(cause);
    }

    public ValidationException(String message, RegistrationObject registrationObject, Throwable cause) {
        this(message, cause);
        this.registrationObject = registrationObject;
    }

    public ValidationException(String message, RegistrationObject registrationObject) {
        this(message);
        this.registrationObject = registrationObject;
    }

    public ValidationException(RegistrationObject registrationObject, Throwable cause) {
        this(cause);
        this.registrationObject = registrationObject;
    }

    public ValidationException(String message, AuthenticationObject authenticationObject, Throwable cause) {
        this(message, cause);
        this.authenticationObject = authenticationObject;
    }

    public ValidationException(String message, AuthenticationObject authenticationObject) {
        this(message);
        this.authenticationObject = authenticationObject;
    }

    public ValidationException(AuthenticationObject authenticationObject, Throwable cause) {
        this(cause);
        this.authenticationObject = authenticationObject;
    }

    public ValidationException(String message, RegistrationObject registrationObject, AuthenticationObject authenticationObject, Throwable cause) {
        this(message, cause);
        this.registrationObject = registrationObject;
        this.authenticationObject = authenticationObject;
    }

    public ValidationException(String message, RegistrationObject registrationObject, AuthenticationObject authenticationObject) {
        this(message);
        this.registrationObject = registrationObject;
        this.authenticationObject = authenticationObject;
    }

    public ValidationException(RegistrationObject registrationObject, AuthenticationObject authenticationObject, Throwable cause) {
        this(cause);
        this.registrationObject = registrationObject;
        this.authenticationObject = authenticationObject;
    }

    public RegistrationObject getRegistrationObject() {
        return registrationObject;
    }

    public AuthenticationObject getAuthenticationObject() {
        return authenticationObject;
    }
}
