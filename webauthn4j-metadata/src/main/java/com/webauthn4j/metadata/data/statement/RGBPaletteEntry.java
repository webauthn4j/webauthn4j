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

package com.webauthn4j.metadata.data.statement;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.Objects;

/**
 * The RGBPaletteEntry is an RGB three-sample tuple palette entry
 */
public class RGBPaletteEntry {

    @NonNull private final Integer r;
    @NonNull private final Integer g;
    @NonNull private final Integer b;

    @JsonCreator
    public RGBPaletteEntry(
            @JsonProperty("r") @NonNull Integer r,
            @JsonProperty("g") @NonNull Integer g,
            @JsonProperty("b") @NonNull Integer b) {
        this.r = r;
        this.g = g;
        this.b = b;
    }

    @NonNull
    public Integer getR() {
        return r;
    }

    @NonNull
    public Integer getG() {
        return g;
    }

    @NonNull
    public Integer getB() {
        return b;
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RGBPaletteEntry that = (RGBPaletteEntry) o;
        return Objects.equals(r, that.r) &&
                Objects.equals(g, that.g) &&
                Objects.equals(b, that.b);
    }

    @Override
    public int hashCode() {

        return Objects.hash(r, g, b);
    }
}
