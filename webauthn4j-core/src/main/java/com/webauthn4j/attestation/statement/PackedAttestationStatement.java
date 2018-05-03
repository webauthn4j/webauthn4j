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
import com.webauthn4j.util.exception.NotImplementedException;

import java.security.cert.CertPath;
import java.security.cert.X509Certificate;
import java.util.Arrays;

@WIP
@JsonIgnoreProperties(value = "format")
@JsonTypeName(PackedAttestationStatement.FORMAT)
public class PackedAttestationStatement implements CertificateBaseAttestationStatement {

    public static final String FORMAT = "packed";

    @JsonProperty
    private String alg;
    @JsonProperty
    private byte[] sig;
    @JsonProperty
    private CertPath x5c;
    @JsonProperty
    private byte[] ecdaaKeyId;

    public PackedAttestationStatement(String alg, byte[] sig, CertPath x5c, byte[] ecdaaKeyId) {
        this.alg = alg;
        this.sig = sig;
        this.x5c = x5c;
        this.ecdaaKeyId = ecdaaKeyId;
    }

    public PackedAttestationStatement(){}

    public String getAlg() {
        return alg;
    }

    public byte[] getSig() {
        return sig;
    }

    @Override
    public CertPath getX5c() {
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

    @JsonIgnore
    @Override
    public AttestationType getAttestationType() {
        throw new NotImplementedException();
    }

    @JsonIgnore
    @Override
    public X509Certificate getEndEntityCertificate() {
        if (x5c.getCertificates().isEmpty()) {
            throw new IllegalStateException();
        }
        return (X509Certificate) x5c.getCertificates().get(0);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof PackedAttestationStatement)) return false;

        PackedAttestationStatement that = (PackedAttestationStatement) o;

        if (alg != null ? !alg.equals(that.alg) : that.alg != null) return false;
        if (!Arrays.equals(sig, that.sig)) return false;
        if (x5c != null ? !x5c.equals(that.x5c) : that.x5c != null) return false;
        return Arrays.equals(ecdaaKeyId, that.ecdaaKeyId);
    }

    @Override
    public int hashCode() {
        int result = alg != null ? alg.hashCode() : 0;
        result = 31 * result + Arrays.hashCode(sig);
        result = 31 * result + (x5c != null ? x5c.hashCode() : 0);
        result = 31 * result + Arrays.hashCode(ecdaaKeyId);
        return result;
    }

}
