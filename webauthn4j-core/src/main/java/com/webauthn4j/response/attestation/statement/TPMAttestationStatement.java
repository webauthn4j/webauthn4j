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

package com.webauthn4j.response.attestation.statement;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeName;

@JsonIgnoreProperties(value = "format")
@JsonTypeName(TPMAttestationStatement.FORMAT)
public class TPMAttestationStatement implements CertificateBaseAttestationStatement {

    public static final String FORMAT = "tpm";
    public static final String VERSION_2_0 = "2.0";

    @JsonProperty
    private String ver;
    @JsonProperty
    private COSEAlgorithmIdentifier alg;
    @JsonProperty
    private AttestationCertificatePath x5c;
    @JsonProperty
    private byte[] ecdaaKeyId;
    @JsonProperty
    private byte[] sig;
    @JsonProperty
    private TPMSAttest certInfo;
    @JsonProperty
    private TPMTPublic pubArea;

    public TPMAttestationStatement(String ver, COSEAlgorithmIdentifier alg, AttestationCertificatePath x5c, byte[] ecdaaKeyId, byte[] sig, TPMSAttest certInfo, TPMTPublic pubArea) {
        this.ver = ver;
        this.alg = alg;
        this.x5c = x5c;
        this.ecdaaKeyId = ecdaaKeyId;
        this.sig = sig;
        this.certInfo = certInfo;
        this.pubArea = pubArea;
    }

    public TPMAttestationStatement(COSEAlgorithmIdentifier alg, AttestationCertificatePath x5c, byte[] ecdaaKeyId, byte[] sig, TPMSAttest certInfo, TPMTPublic pubArea) {
        this.ver = VERSION_2_0;
        this.alg = alg;
        this.x5c = x5c;
        this.ecdaaKeyId = ecdaaKeyId;
        this.sig = sig;
        this.certInfo = certInfo;
        this.pubArea = pubArea;
    }


    public TPMAttestationStatement(){}

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

    public byte[] getEcdaaKeyId() {
        return ecdaaKeyId;
    }

    public byte[] getSig() {
        return sig;
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

    }
}
