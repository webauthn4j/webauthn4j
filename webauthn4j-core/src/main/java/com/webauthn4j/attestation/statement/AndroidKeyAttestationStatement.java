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

import com.fasterxml.jackson.annotation.JsonProperty;
import com.webauthn4j.validator.exception.ConstraintViolationException;

public class AndroidKeyAttestationStatement implements CertificateBaseAttestationStatement {

    public static final String FORMAT = "android-key";

    @JsonProperty
    private COSEAlgorithmIdentifier alg;

    @JsonProperty
    private byte[] sig;

    @JsonProperty
    private AttestationCertificatePath x5c;

    public AndroidKeyAttestationStatement(COSEAlgorithmIdentifier alg, byte[] sig, AttestationCertificatePath x5c) {
        this.alg = alg;
        this.sig = sig;
        this.x5c = x5c;
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

    @Override
    public String getFormat() {
        return FORMAT;
    }

    @Override
    public void validate() {
        if (alg == null) {
            throw new ConstraintViolationException("alg must not be null");
        }
        if (sig == null) {
            throw new ConstraintViolationException("sig must not be null");
        }
        if (x5c == null) {
            throw new ConstraintViolationException("x5c must not be null");
        }
    }
}
