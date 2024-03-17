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

package com.webauthn4j.validator.exception;

import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import org.checkerframework.checker.nullness.qual.Nullable;

/**
 * Thrown if bad algorithm is specified
 */
@SuppressWarnings("squid:S110")
public class BadAlgorithmException extends ValidationException {

    private final COSEAlgorithmIdentifier actual;
    private final COSEAlgorithmIdentifier expected;

    public BadAlgorithmException(@Nullable String message, @Nullable COSEAlgorithmIdentifier actual, @Nullable COSEAlgorithmIdentifier expected, @Nullable Throwable cause) {
        super(message, cause);
        this.actual = actual;
        this.expected = expected;
    }

    public BadAlgorithmException(@Nullable String message, @Nullable COSEAlgorithmIdentifier actual, @Nullable COSEAlgorithmIdentifier expected) {
        super(message);
        this.actual = actual;
        this.expected = expected;
    }

    public BadAlgorithmException(@Nullable String message, @Nullable Throwable cause) {
        super(message, cause);
        this.actual = null;
        this.expected = null;
    }

    public BadAlgorithmException(@Nullable String message) {
        super(message);
        this.actual = null;
        this.expected = null;
    }

    public BadAlgorithmException(@Nullable Throwable cause) {
        super(cause);
        this.actual = null;
        this.expected = null;
    }

    public COSEAlgorithmIdentifier getActual() {
        return actual;
    }

    public COSEAlgorithmIdentifier getExpected() {
        return expected;
    }
}
