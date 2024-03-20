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
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.math.BigInteger;
import java.util.List;
import java.util.Objects;

/**
 * The DisplayPNGCharacteristicsDescriptor describes a PNG image characteristics as defined in the PNG spec for IHDR (image header) and PLTE (palette table)
 */
public class DisplayPNGCharacteristicsDescriptor {

    @NonNull private final BigInteger width;
    @NonNull private final BigInteger height;
    @NonNull private final Short bitDepth;
    @NonNull private final Short colorType;
    @NonNull private final Short compression;
    @NonNull private final Short filter;
    @NonNull private final Short interlace;
    @Nullable private final List<RGBPaletteEntry> plte;

    @JsonCreator
    public DisplayPNGCharacteristicsDescriptor(
            @JsonProperty("width") @NonNull BigInteger width,
            @JsonProperty("height") @NonNull BigInteger height,
            @JsonProperty("bitDepth") @NonNull Short bitDepth,
            @JsonProperty("colorType") @NonNull Short colorType,
            @JsonProperty("compression") @NonNull Short compression,
            @JsonProperty("filter") @NonNull Short filter,
            @JsonProperty("interlace") @NonNull Short interlace,
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

    @NonNull public BigInteger getWidth() {
        return width;
    }

    @NonNull public BigInteger getHeight() {
        return height;
    }

    @NonNull public Short getBitDepth() {
        return bitDepth;
    }

    @NonNull public Short getColorType() {
        return colorType;
    }

    @NonNull public Short getCompression() {
        return compression;
    }

    @NonNull public Short getFilter() {
        return filter;
    }

    @NonNull public Short getInterlace() {
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
