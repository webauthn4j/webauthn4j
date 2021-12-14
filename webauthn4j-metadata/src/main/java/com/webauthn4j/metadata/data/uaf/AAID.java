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

package com.webauthn4j.metadata.data.uaf;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.Objects;

public class AAID {

    private final int v;
    private final int m;

    public AAID(@NonNull String aaid) {
        String[] array = aaid.split("#");
        if (array.length != 2) {
            throw new IllegalArgumentException("AAID value is not divided by single '#' separator.");
        }
        if (array[0].length() != 4) {
            throw new IllegalArgumentException("V part of AAID must consists of 4 hexadecimal digits.");
        }
        if (array[1].length() != 4) {
            throw new IllegalArgumentException("M part of AAID must consists of 4 hexadecimal digits.");
        }
        v = Integer.parseInt(array[0], 16);
        m = Integer.parseInt(array[1], 16);
    }

    @JsonCreator
    static AAID deserialize(@NonNull String aaid) throws InvalidFormatException {
        try {
            return new AAID(aaid);
        } catch (IllegalArgumentException e) {
            throw new InvalidFormatException(null, "invalid aaid", aaid, AAID.class);
        }
    }

    public int getV() {
        return v;
    }

    public int getM() {
        return m;
    }

    @NonNull
    @JsonValue
    @Override
    public String toString() {
        return String.format("%04X", v) + "#" + String.format("%04X", m);
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AAID aaid = (AAID) o;
        return v == aaid.v &&
                m == aaid.m;
    }

    @Override
    public int hashCode() {
        return Objects.hash(v, m);
    }
}
