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
import com.webauthn4j.util.CollectionUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.math.BigInteger;
import java.util.List;
import java.util.Objects;

/**
 * The DisplayPNGCharacteristicsDescriptor describes a PNG image characteristics as defined in the PNG spec for IHDR (image header) and PLTE (palette table)
 */
public class DisplayPNGCharacteristicsDescriptor {

    @NotNull private final BigInteger width;
    @NotNull private final BigInteger height;
    @NotNull private final Short bitDepth;
    @NotNull private final Short colorType;
    @NotNull private final Short compression;
    @NotNull private final Short filter;
    @NotNull private final Short interlace;
    @Nullable private final List<RGBPaletteEntry> plte;

    @JsonCreator
    public DisplayPNGCharacteristicsDescriptor(
            @JsonProperty("width") @NotNull BigInteger width,
            @JsonProperty("height") @NotNull BigInteger height,
            @JsonProperty("bitDepth") @NotNull Short bitDepth,
            @JsonProperty("colorType") @NotNull Short colorType,
            @JsonProperty("compression") @NotNull Short compression,
            @JsonProperty("filter") @NotNull Short filter,
            @JsonProperty("interlace") @NotNull Short interlace,
            @JsonProperty("plte") @Nullable List<RGBPaletteEntry> plte) {
        this.width = width;
        this.height = height;
        this.bitDepth = bitDepth;
        this.colorType = colorType;
        this.compression = compression;
        this.filter = filter;
        this.interlace = interlace;
        this.plte = CollectionUtil.unmodifiableList(plte);
    }

    @NotNull public BigInteger getWidth() {
        return width;
    }

    @NotNull public BigInteger getHeight() {
        return height;
    }

    @NotNull public Short getBitDepth() {
        return bitDepth;
    }

    @NotNull public Short getColorType() {
        return colorType;
    }

    @NotNull public Short getCompression() {
        return compression;
    }

    @NotNull public Short getFilter() {
        return filter;
    }

    @NotNull public Short getInterlace() {
        return interlace;
    }

    @Nullable public List<RGBPaletteEntry> getPlte() {
        return plte;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DisplayPNGCharacteristicsDescriptor that = (DisplayPNGCharacteristicsDescriptor) o;
        return Objects.equals(width, that.width) &&
                Objects.equals(height, that.height) &&
                Objects.equals(bitDepth, that.bitDepth) &&
                Objects.equals(colorType, that.colorType) &&
                Objects.equals(compression, that.compression) &&
                Objects.equals(filter, that.filter) &&
                Objects.equals(interlace, that.interlace) &&
                Objects.equals(plte, that.plte);
    }

    @Override
    public int hashCode() {

        return Objects.hash(width, height, bitDepth, colorType, compression, filter, interlace, plte);
    }
}
