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

import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.List;

public class NotAllowedAlgorithmException extends ValidationException {

    private final List<COSEAlgorithmIdentifier> expected;
    private final COSEAlgorithmIdentifier actual;

    public NotAllowedAlgorithmException(@Nullable String message, @Nullable List<COSEAlgorithmIdentifier> expected, @Nullable COSEAlgorithmIdentifier actual, @Nullable Throwable cause) {
        super(message, cause);
        this.expected = expected;
        this.actual = actual;
    }

    public NotAllowedAlgorithmException(@Nullable String message, @Nullable List<COSEAlgorithmIdentifier> expected, @Nullable COSEAlgorithmIdentifier actual) {
        super(message);
        this.expected = expected;
        this.actual = actual;
    }

    public NotAllowedAlgorithmException(@Nullable String message, @Nullable Throwable cause) {
        super(message, cause);
        this.expected = null;
        this.actual = null;
    }

    public NotAllowedAlgorithmException(@Nullable String message) {
        super(message);
        this.expected = null;
        this.actual = null;
    }

    public NotAllowedAlgorithmException(@Nullable Throwable cause) {
        super(cause);
        this.expected = null;
        this.actual = null;
    }

    public List<COSEAlgorithmIdentifier> getExpected() {
        return expected;
    }

    public COSEAlgorithmIdentifier getActual() {
        return actual;
    }
}
