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

import com.fasterxml.jackson.annotation.*;

import java.security.cert.CertPath;
import java.security.cert.X509Certificate;
import java.util.Arrays;

@JsonIgnoreProperties(value = "format")
@JsonTypeName(FIDOU2FAttestationStatement.FORMAT)
public class FIDOU2FAttestationStatement implements CertificateBaseAttestationStatement {

    public static final String FORMAT = "fido-u2f";

    @JsonProperty
    private CertPath x5c;
    @JsonProperty
    private byte[] sig;

    public FIDOU2FAttestationStatement(CertPath x5c, byte[] sig) {
        this.x5c = x5c;
        this.sig = sig;
    }

    public FIDOU2FAttestationStatement(){}

    @Override
    public CertPath getX5c() {
        return x5c;
    }

    public byte[] getSig() {
        return sig;
    }

    @Override
    public String getFormat() {
        return FORMAT;
    }

    /**
     * {@link AttestationType}.Basic is always returned as RP cannot differentiate between Basic and Privacy CA from the attestation data,
     * @return AttestationType.Basic
     */
    @JsonIgnore
    @Override
    public AttestationType getAttestationType() {
        return AttestationType.Basic;
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
        if (!(o instanceof FIDOU2FAttestationStatement)) return false;

        FIDOU2FAttestationStatement that = (FIDOU2FAttestationStatement) o;

        if (x5c != null ? !x5c.equals(that.x5c) : that.x5c != null) return false;
        return Arrays.equals(sig, that.sig);
    }

    @Override
    public int hashCode() {
        int result = x5c != null ? x5c.hashCode() : 0;
        result = 31 * result + Arrays.hashCode(sig);
        return result;
    }
}
