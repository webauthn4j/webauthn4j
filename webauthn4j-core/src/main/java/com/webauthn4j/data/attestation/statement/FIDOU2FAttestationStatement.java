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

package com.webauthn4j.data.attestation.statement;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.webauthn4j.util.ArrayUtil;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.validator.exception.ConstraintViolationException;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.Arrays;
import java.util.Objects;

@JsonIgnoreProperties(value = "format")
@JsonTypeName(FIDOU2FAttestationStatement.FORMAT)
public class FIDOU2FAttestationStatement implements CertificateBaseAttestationStatement {

    public static final String FORMAT = "fido-u2f";

    @JsonProperty
    private final AttestationCertificatePath x5c;

    @JsonProperty
    private final byte[] sig;

    @JsonCreator
    public FIDOU2FAttestationStatement(
            @NonNull @JsonProperty("x5c") AttestationCertificatePath x5c,
            @NonNull @JsonProperty("sig") byte[] sig) {
        AssertUtil.notNull(x5c, "x5c must not be null");
        AssertUtil.notNull(sig, "sig must not be null");
        this.x5c = x5c;
        this.sig = sig;
    }

    @Override
    public @NonNull AttestationCertificatePath getX5c() {
        return x5c;
    }

    public @NonNull byte[] getSig() {
        return ArrayUtil.clone(sig);
    }

    @Override
    public @NonNull String getFormat() {
        return FORMAT;
    }

    @Override
    public void validate() {
        if (x5c.size() != 1) {
            throw new ConstraintViolationException("x5c must have exactly one certificate");
        }
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        FIDOU2FAttestationStatement that = (FIDOU2FAttestationStatement) o;
        return Objects.equals(x5c, that.x5c) &&
                Arrays.equals(sig, that.sig);
    }

    @Override
    public int hashCode() {

        int result = Objects.hash(x5c);
        result = 31 * result + Arrays.hashCode(sig);
        return result;
    }

    @Override
    public String toString() {
        return "FIDOU2FAttestationStatement(" +
                "x5c=" + x5c +
                ", sig=" + ArrayUtil.toHexString(sig) +
                ')';
    }
}
