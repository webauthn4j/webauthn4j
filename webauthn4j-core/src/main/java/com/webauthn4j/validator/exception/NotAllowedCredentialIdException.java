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

import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.List;

public class NotAllowedCredentialIdException extends ValidationException {

    private final List<byte[]> expected;
    private final byte[] actual;

    public NotAllowedCredentialIdException(@Nullable String message, @Nullable List<byte[]> expected, @Nullable byte[] actual, @Nullable Throwable cause) {
        super(message, cause);
        this.expected = expected;
        this.actual = actual;
    }

    public NotAllowedCredentialIdException(@Nullable String message, @Nullable List<byte[]> expected, @Nullable byte[] actual) {
        super(message);
        this.expected = expected;
        this.actual = actual;
    }


    public NotAllowedCredentialIdException(@Nullable String message, @Nullable Throwable cause) {
        super(message, cause);
        this.expected = null;
        this.actual = null;
    }

    public NotAllowedCredentialIdException(@Nullable String message) {
        super(message);
        this.expected = null;
        this.actual = null;
    }

    public NotAllowedCredentialIdException(@Nullable Throwable cause) {
        super(cause);
        this.expected = null;
        this.actual = null;
    }

    public List<byte[]> getExpected() {
        return expected;
    }

    public byte[] getActual() {
        return actual;
    }
}
