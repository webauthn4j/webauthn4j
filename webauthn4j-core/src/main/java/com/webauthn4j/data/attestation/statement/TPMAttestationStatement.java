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

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.webauthn4j.util.ArrayUtil;
import com.webauthn4j.validator.exception.ConstraintViolationException;

import java.util.Arrays;
import java.util.Objects;

@JsonIgnoreProperties(value = "format")
@JsonTypeName(TPMAttestationStatement.FORMAT)
public class TPMAttestationStatement implements CertificateBaseAttestationStatement {

    public static final String FORMAT = "tpm";
    public static final String VERSION_2_0 = "2.0";

    @JsonProperty
    private final String ver;
    @JsonProperty
    private final COSEAlgorithmIdentifier alg;
    @JsonProperty
    private final AttestationCertificatePath x5c;
    @JsonProperty
    private final byte[] sig;
    @JsonProperty
    private final TPMSAttest certInfo;
    @JsonProperty
    private final TPMTPublic pubArea;

    public TPMAttestationStatement(
            @JsonProperty("ver") String ver,
            @JsonProperty("alg") COSEAlgorithmIdentifier alg,
            @JsonProperty("x5c") AttestationCertificatePath x5c,
            @JsonProperty("sig") byte[] sig,
            @JsonProperty("certInfo") TPMSAttest certInfo,
            @JsonProperty("pubArea") TPMTPublic pubArea) {
        this.ver = ver;
        this.alg = alg;
        this.x5c = x5c;
        this.sig = sig;
        this.certInfo = certInfo;
        this.pubArea = pubArea;
    }

    public TPMAttestationStatement(COSEAlgorithmIdentifier alg, AttestationCertificatePath x5c, byte[] sig, TPMSAttest certInfo, TPMTPublic pubArea) {
        this.ver = VERSION_2_0;
        this.alg = alg;
        this.x5c = x5c;
        this.sig = sig;
        this.certInfo = certInfo;
        this.pubArea = pubArea;
    }

    public String getVer() {
        return ver;
    }

    public COSEAlgorithmIdentifier getAlg() {
        return alg;
    }

    @Override
    public AttestationCertificatePath getX5c() {
        return x5c;
    }

    public byte[] getSig() {
        return ArrayUtil.clone(sig);
    }

    public TPMSAttest getCertInfo() {
        return certInfo;
    }

    public TPMTPublic getPubArea() {
        return pubArea;
    }

    @Override
    public String getFormat() {
        return FORMAT;
    }

    @Override
    public void validate() {
        if (x5c == null) {
            throw new ConstraintViolationException("x5c must be present");
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TPMAttestationStatement that = (TPMAttestationStatement) o;
        return Objects.equals(ver, that.ver) &&
                Objects.equals(alg, that.alg) &&
                Objects.equals(x5c, that.x5c) &&
                Arrays.equals(sig, that.sig) &&
                Objects.equals(certInfo, that.certInfo) &&
                Objects.equals(pubArea, that.pubArea);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(ver, alg, x5c, certInfo, pubArea);
        result = 31 * result + Arrays.hashCode(sig);
        return result;
    }
}
