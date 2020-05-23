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

package com.webauthn4j.metadata.data.statement;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.webauthn4j.util.CollectionUtil;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.List;
import java.util.Objects;

/**
 * The DisplayPNGCharacteristicsDescriptor describes a PNG image characteristics as defined in the PNG spec for IHDR (image header) and PLTE (palette table)
 */
public class DisplayPNGCharacteristicsDescriptor implements Serializable {

    private final BigInteger width;
    private final BigInteger height;
    private final Short bitDepth;
    private final Short colorType;
    private final Short compression;
    private final Short filter;
    private final Short interlace;
    private final List<RGBPaletteEntry> plte;

    @JsonCreator
    public DisplayPNGCharacteristicsDescriptor(
            @JsonProperty("width") BigInteger width,
            @JsonProperty("height") BigInteger height,
            @JsonProperty("bitDepth") Short bitDepth,
            @JsonProperty("colorType") Short colorType,
            @JsonProperty("compression") Short compression,
            @JsonProperty("filter") Short filter,
            @JsonProperty("interlace") Short interlace,
            @JsonProperty("plte") List<RGBPaletteEntry> plte) {
        this.width = width;
        this.height = height;
        this.bitDepth = bitDepth;
        this.colorType = colorType;
        this.compression = compression;
        this.filter = filter;
        this.interlace = interlace;
        this.plte = CollectionUtil.unmodifiableList(plte);
    }

    public BigInteger getWidth() {
        return width;
    }

    public BigInteger getHeight() {
        return height;
    }

    public Short getBitDepth() {
        return bitDepth;
    }

    public Short getColorType() {
        return colorType;
    }

    public Short getCompression() {
        return compression;
    }

    public Short getFilter() {
        return filter;
    }

    public Short getInterlace() {
        return interlace;
    }

    public List<RGBPaletteEntry> getPlte() {
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
