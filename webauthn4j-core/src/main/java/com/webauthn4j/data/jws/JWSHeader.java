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

package com.webauthn4j.data.jws;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.security.cert.CertPath;
import java.util.Objects;

public class JWSHeader {

    private final JWAIdentifier alg;
    private final CertPath x5c;

    public JWSHeader(
            @Nullable @JsonProperty("alg") JWAIdentifier alg,
            @Nullable @JsonProperty("x5c") CertPath x5c) {
        this.alg = alg;
        this.x5c = x5c;
    }

    public @Nullable JWAIdentifier getAlg() {
        return alg;
    }

    public @Nullable CertPath getX5c() {
        return x5c;
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        JWSHeader jwsHeader = (JWSHeader) o;
        return alg == jwsHeader.alg &&
                Objects.equals(x5c, jwsHeader.x5c);
    }

    @Override
    public int hashCode() {

        return Objects.hash(alg, x5c);
    }

    @Override
    public String toString() {
        return "JWSHeader(" +
                "alg=" + alg +
                ", x5c=" + x5c +
                ')';
    }
}
