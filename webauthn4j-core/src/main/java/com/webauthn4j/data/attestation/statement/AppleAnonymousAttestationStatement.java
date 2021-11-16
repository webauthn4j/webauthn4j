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

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.validator.exception.ConstraintViolationException;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.Objects;

@JsonIgnoreProperties(value = "format")
@JsonTypeName(AppleAnonymousAttestationStatement.FORMAT)
public class AppleAnonymousAttestationStatement implements CertificateBaseAttestationStatement {

    public static final String FORMAT = "apple";

    @JsonProperty
    private final AttestationCertificatePath x5c;

    public AppleAnonymousAttestationStatement(
            @NonNull @JsonProperty("x5c") AttestationCertificatePath x5c) {
        AssertUtil.notNull(x5c, "x5c must not be null");
        this.x5c = x5c;
    }

    @Override
    public @NonNull AttestationCertificatePath getX5c() {
        return x5c;
    }

    @JsonIgnore
    @Override
    public @NonNull String getFormat() {
        return FORMAT;
    }

    @Override
    public void validate() {
        if (x5c.isEmpty()) {
            throw new ConstraintViolationException("No attestation certificate is found in apple anonymous attestation statement.");
        }
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AppleAnonymousAttestationStatement that = (AppleAnonymousAttestationStatement) o;
        return Objects.equals(x5c, that.x5c);
    }

    @Override
    public int hashCode() {
        return Objects.hash(x5c);
    }

    @Override
    public String toString() {
        return "AppleAnonymousAttestationStatement(" +
                "x5c=" + x5c +
                ')';
    }
}