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
import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.Objects;

/**
 * In the case of ECDAA attestation, the ECDAA-Issuer's trust anchor must be specified in this field.
 */
public class EcdaaTrustAnchor {
    @NotNull private final String x;
    @NotNull private final String y;
    @NotNull private final String c;
    @NotNull private final String sx;
    @NotNull private final String sy;
    @NotNull private final String g1Curve;

    @JsonCreator
    public EcdaaTrustAnchor(
            @JsonProperty("X") @NotNull String x,
            @JsonProperty("Y") @NotNull String y,
            @JsonProperty("c") @NotNull String c,
            @JsonProperty("sx") @NotNull String sx,
            @JsonProperty("sy") @NotNull String sy,
            @JsonProperty("G1Curve") @NotNull String g1Curve) {
        this.x = x;
        this.y = y;
        this.c = c;
        this.sx = sx;
        this.sy = sy;
        this.g1Curve = g1Curve;
    }

    @NotNull
    @JsonGetter("X")
    public String getX() {
        return x;
    }

    @NotNull
    @JsonGetter("Y")
    public String getY() {
        return y;
    }

    @NotNull
    @JsonGetter("c")
    public String getC() {
        return c;
    }

    @NotNull
    @JsonGetter("sx")
    public String getSx() {
        return sx;
    }

    @NotNull
    @JsonGetter("sy")
    public String getSy() {
        return sy;
    }

    @NotNull
    @JsonGetter("G1Curve")
    public String getG1Curve() {
        return g1Curve;
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        EcdaaTrustAnchor that = (EcdaaTrustAnchor) o;
        return Objects.equals(x, that.x) &&
                Objects.equals(y, that.y) &&
                Objects.equals(c, that.c) &&
                Objects.equals(sx, that.sx) &&
                Objects.equals(sy, that.sy) &&
                Objects.equals(g1Curve, that.g1Curve);
    }

    @Override
    public int hashCode() {

        return Objects.hash(x, y, c, sx, sy, g1Curve);
    }
}
