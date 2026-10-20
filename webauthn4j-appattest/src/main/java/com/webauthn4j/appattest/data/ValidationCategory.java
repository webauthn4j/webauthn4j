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

package com.webauthn4j.appattest.data;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/**
 * An unsigned 32-bit App Attest launch validation category.
 * Unknown values are preserved to support future categories.
 */
public final class ValidationCategory {

    public static final ValidationCategory INVALID = new ValidationCategory(0);
    public static final ValidationCategory OPERATING_SYSTEM = new ValidationCategory(1);
    public static final ValidationCategory TEST_FLIGHT = new ValidationCategory(2);
    public static final ValidationCategory DEVELOPMENT = new ValidationCategory(3);
    public static final ValidationCategory APP_STORE = new ValidationCategory(4);
    public static final ValidationCategory ENTERPRISE_OR_AD_HOC = new ValidationCategory(5);
    public static final ValidationCategory DEVELOPER_ID = new ValidationCategory(6);
    public static final ValidationCategory OTHER = new ValidationCategory(10);

    private final long value;

    private ValidationCategory(long value) {
        this.value = value;
    }

    public static @NotNull ValidationCategory create(long value) {
        if (value < 0 || value > 0xffff_ffffL) {
            throw new IllegalArgumentException("value must be an unsigned 32-bit integer");
        }
        return new ValidationCategory(value);
    }

    public long getValue() {
        return value;
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (!(o instanceof ValidationCategory)) return false;
        return value == ((ValidationCategory) o).value;
    }

    @Override
    public int hashCode() {
        return Long.hashCode(value);
    }

    @Override
    public @NotNull String toString() {
        return Long.toString(value);
    }
}
