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
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.Objects;

/**
 * The RGBPaletteEntry is an RGB three-sample tuple palette entry
 */
public class RGBPaletteEntry {

    @NotNull private final Integer r;
    @NotNull private final Integer g;
    @NotNull private final Integer b;

    @JsonCreator
    public RGBPaletteEntry(
            @JsonProperty("r") @NotNull Integer r,
            @JsonProperty("g") @NotNull Integer g,
            @JsonProperty("b") @NotNull Integer b) {
        this.r = r;
        this.g = g;
        this.b = b;
    }

    @NotNull
    public Integer getR() {
        return r;
    }

    @NotNull
    public Integer getG() {
        return g;
    }

    @NotNull
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
