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

package com.webauthn4j.appattest.data.attestation.statement;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.webauthn4j.data.attestation.statement.AttestationCertificatePath;
import com.webauthn4j.data.attestation.statement.CertificateBaseAttestationStatement;
import com.webauthn4j.util.ArrayUtil;
import com.webauthn4j.util.AssertUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import tools.jackson.databind.exc.MismatchedInputException;

import java.util.Arrays;
import java.util.Objects;

@JsonIgnoreProperties(value = "format")
@JsonTypeName(AppleAppAttestAttestationStatement.FORMAT)
public class AppleAppAttestAttestationStatement implements CertificateBaseAttestationStatement {
    public static final String FORMAT = "apple-appattest";

    @JsonProperty
    private final AttestationCertificatePath x5c;

    @JsonProperty
    private final byte[] receipt;

    public AppleAppAttestAttestationStatement(
            @NotNull @JsonProperty("x5c") AttestationCertificatePath x5c,
            @NotNull @JsonProperty("receipt") byte[] receipt) {
        AssertUtil.notNull(x5c, "x5c must not be null");
        AssertUtil.notNull(receipt, "receipt must not be null");
        this.x5c = x5c;
        this.receipt = receipt;
    }

    @SuppressWarnings("unused")
    @JsonCreator
    private static AppleAppAttestAttestationStatement deserialize(
            @NotNull @JsonProperty("x5c") AttestationCertificatePath x5c,
            @NotNull @JsonProperty("receipt") byte[] receipt) throws MismatchedInputException {
        try {
            return new AppleAppAttestAttestationStatement(x5c, receipt);
        } catch (IllegalArgumentException e) {
            throw MismatchedInputException.from(null, AppleAppAttestAttestationStatement.class, "failed to parse");
        }
    }

    public @NotNull byte[] getReceipt() {
        return ArrayUtil.clone(receipt);
    }

    @Override
    public @NotNull AttestationCertificatePath getX5c() {
        return x5c;
    }

    @Override
    public @NotNull String getFormat() {
        return FORMAT;
    }

    @Override
    public void validate() {
        //nop
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AppleAppAttestAttestationStatement that = (AppleAppAttestAttestationStatement) o;
        return Objects.equals(x5c, that.x5c) &&
                Arrays.equals(receipt, that.receipt);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(x5c);
        result = 31 * result + Arrays.hashCode(receipt);
        return result;
    }
}
