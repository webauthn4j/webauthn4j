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

import com.webauthn4j.data.client.Origin;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.Set;

/**
 * Thrown if bad origin is specified
 */
@SuppressWarnings("squid:S110")
public class BadOriginException extends ValidationException {

    private final Set<Origin> expected;
    private final Origin actual;

    public BadOriginException(@Nullable String message, @Nullable Set<Origin> expected, @Nullable Origin actual, @Nullable Throwable cause) {
        super(message, cause);
        this.expected = expected;
        this.actual = actual;
    }

    public BadOriginException(@Nullable String message, @Nullable Set<Origin> expected, @Nullable Origin actual) {
        super(message);
        this.expected = expected;
        this.actual = actual;
    }

    public BadOriginException(@Nullable String message, @Nullable Throwable cause) {
        super(message, cause);
        this.expected = null;
        this.actual = null;
    }

    public BadOriginException(@Nullable String message) {
        super(message);
        this.expected = null;
        this.actual = null;
    }

    public BadOriginException(@Nullable Throwable cause) {
        super(cause);
        this.expected = null;
        this.actual = null;
    }

    public Set<Origin> getExpected() {
        return expected;
    }

    public Origin getActual() {
        return actual;
    }
}
