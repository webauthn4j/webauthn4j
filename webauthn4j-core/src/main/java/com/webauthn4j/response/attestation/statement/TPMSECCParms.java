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

import java.nio.ByteBuffer;

public class TPMSECCParms implements TPMUPublicParms {

    private byte[] symmetric;
    private byte[] scheme;
    private byte[] curveId;
    private byte[] kdf;

    public TPMSECCParms(byte[] symmetric, byte[] scheme, byte[] curveId, byte[] kdf) {
        this.symmetric = symmetric;
        this.scheme = scheme;
        this.curveId = curveId;
        this.kdf = kdf;
    }

    public byte[] getSymmetric() {
        return symmetric;
    }

    public byte[] getScheme() {
        return scheme;
    }

    public byte[] getCurveId() {
        return curveId;
    }

    public byte[] getKdf() {
        return kdf;
    }

    @Override
    public byte[] getBytes() {
        return ByteBuffer.allocate(8)
                .put(symmetric)
                .put(scheme)
                .put(curveId)
                .put(kdf)
                .array();
    }
}
