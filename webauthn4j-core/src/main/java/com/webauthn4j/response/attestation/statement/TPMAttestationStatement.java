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

public class TPMAttestationStatement implements CertificateBaseAttestationStatement {

    public static final String FORMAT = "tpm";

    private COSEAlgorithmIdentifier alg;
    private AttestationCertificatePath x5c;
    private byte[] ecdaaKeyId;
    private byte[] sig;
    private CertInfo certInfo;
    private PubArea pubArea;


    @Override
    public AttestationCertificatePath getX5c() {
        return null;
    }

    @Override
    public String getFormat() {
        return FORMAT;
    }

    @Override
    public void validate() {

    }
}
