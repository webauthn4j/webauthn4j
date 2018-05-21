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

package com.webauthn4j.attestation.statement;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.webauthn4j.validator.exception.ConstraintViolationException;

import java.util.Arrays;
import java.util.Objects;

@JsonIgnoreProperties(value = "format")
@JsonTypeName(FIDOU2FAttestationStatement.FORMAT)
public class FIDOU2FAttestationStatement implements CertificateBaseAttestationStatement {

    public static final String FORMAT = "fido-u2f";

    @JsonProperty
    private AttestationCertificatePath x5c;

    @JsonProperty
    private byte[] sig;

    public FIDOU2FAttestationStatement(AttestationCertificatePath x5c, byte[] sig) {
        this.x5c = x5c;
        this.sig = sig;
    }

    public FIDOU2FAttestationStatement() {
    }

    @Override
    public AttestationCertificatePath getX5c() {
        return x5c;
    }

    public byte[] getSig() {
        return sig;
    }

    @Override
    public String getFormat() {
        return FORMAT;
    }

    @Override
    public void validate() {
        if (x5c == null) {
            throw new ConstraintViolationException("x5c must not be null");
        }
        if (x5c.size() != 1) {
            throw new ConstraintViolationException("x5c must have exactly one certificate");
        }

        if (sig == null) {
            throw new ConstraintViolationException("sig must not be null");
        }
    }

    @Override
    public boolean equals(Object o) {
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
}
