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
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.Objects;

/**
 * In the case of ECDAA attestation, the ECDAA-Issuer's trust anchor must be specified in this field.
 */
public class EcdaaTrustAnchor {
    @NonNull private final String x;
    @NonNull private final String y;
    @NonNull private final String c;
    @NonNull private final String sx;
    @NonNull private final String sy;
    @NonNull private final String g1Curve;

    @JsonCreator
    public EcdaaTrustAnchor(
            @JsonProperty("X") @NonNull String x,
            @JsonProperty("Y") @NonNull String y,
            @JsonProperty("c") @NonNull String c,
            @JsonProperty("sx") @NonNull String sx,
            @JsonProperty("sy") @NonNull String sy,
            @JsonProperty("G1Curve") @NonNull String g1Curve) {
        this.x = x;
        this.y = y;
        this.c = c;
        this.sx = sx;
        this.sy = sy;
        this.g1Curve = g1Curve;
    }

    @NonNull
    @JsonGetter("X")
    public String getX() {
        return x;
    }

    @NonNull
    @JsonGetter("Y")
    public String getY() {
        return y;
    }

    @NonNull
    @JsonGetter("c")
    public String getC() {
        return c;
    }

    @NonNull
    @JsonGetter("sx")
    public String getSx() {
        return sx;
    }

    @NonNull
    @JsonGetter("sy")
    public String getSy() {
        return sy;
    }

    @NonNull
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
