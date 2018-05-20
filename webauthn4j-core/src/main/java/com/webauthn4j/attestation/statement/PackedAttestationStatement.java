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

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.webauthn4j.util.WIP;
import com.webauthn4j.validator.exception.ConstraintViolationException;

import java.util.Arrays;
import java.util.Objects;

@WIP
@JsonIgnoreProperties(value = "format")
@JsonTypeName(PackedAttestationStatement.FORMAT)
public class PackedAttestationStatement implements CertificateBaseAttestationStatement {

    public static final String FORMAT = "packed";

    @JsonProperty
    private COSEAlgorithmIdentifier alg;

    @JsonProperty
    private byte[] sig;

    @JsonProperty
    private AttestationCertificatePath x5c;

    @JsonProperty
    private byte[] ecdaaKeyId;

    public PackedAttestationStatement(COSEAlgorithmIdentifier alg, byte[] sig, AttestationCertificatePath x5c, byte[] ecdaaKeyId) {
        this.alg = alg;
        this.sig = sig;
        this.x5c = x5c;
        this.ecdaaKeyId = ecdaaKeyId;
    }

    public PackedAttestationStatement() {
    }

    public COSEAlgorithmIdentifier getAlg() {
        return alg;
    }

    public byte[] getSig() {
        return sig;
    }

    @Override
    public AttestationCertificatePath getX5c() {
        return x5c;
    }

    public byte[] getEcdaaKeyId() {
        return ecdaaKeyId;
    }

    @JsonIgnore
    @Override
    public String getFormat() {
        return FORMAT;
    }

    @Override
    public void validate() {
        if (x5c == null && ecdaaKeyId == null) {
            throw new ConstraintViolationException("x5c or ecdaaKeyId must not be null");
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PackedAttestationStatement that = (PackedAttestationStatement) o;
        return alg == that.alg &&
                Arrays.equals(sig, that.sig) &&
                Objects.equals(x5c, that.x5c) &&
                Arrays.equals(ecdaaKeyId, that.ecdaaKeyId);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(alg, x5c);
        result = 31 * result + Arrays.hashCode(sig);
        result = 31 * result + Arrays.hashCode(ecdaaKeyId);
        return result;
    }
}
