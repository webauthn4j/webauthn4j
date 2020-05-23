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

import com.webauthn4j.util.ArrayUtil;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Objects;

public class TPMSECCParms implements TPMUPublicParms {

    private final byte[] symmetric;
    private final byte[] scheme;
    private final TPMEccCurve curveId;
    private final byte[] kdf;

    public TPMSECCParms(byte[] symmetric, byte[] scheme, TPMEccCurve curveId, byte[] kdf) {
        this.symmetric = symmetric;
        this.scheme = scheme;
        this.curveId = curveId;
        this.kdf = kdf;
    }

    public byte[] getSymmetric() {
        return ArrayUtil.clone(symmetric);
    }

    public byte[] getScheme() {
        return ArrayUtil.clone(scheme);
    }

    public TPMEccCurve getCurveId() {
        return curveId;
    }

    public byte[] getKdf() {
        return ArrayUtil.clone(kdf);
    }

    @Override
    public byte[] getBytes() {
        return ByteBuffer.allocate(8)
                .put(symmetric)
                .put(scheme)
                .put(curveId.getBytes())
                .put(kdf)
                .array();
    }

    public void validate() {
        if (symmetric.length != 2) {
            throw new IllegalStateException("symmetric must be length 2");
        }
        if (scheme.length != 2) {
            throw new IllegalStateException("scheme must be length 2");
        }
        if (kdf.length != 2) {
            throw new IllegalStateException("kdf must be length 2");
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TPMSECCParms that = (TPMSECCParms) o;
        return Arrays.equals(symmetric, that.symmetric) &&
                Arrays.equals(scheme, that.scheme) &&
                curveId == that.curveId &&
                Arrays.equals(kdf, that.kdf);
    }

    @Override
    public int hashCode() {

        int result = Objects.hash(curveId);
        result = 31 * result + Arrays.hashCode(symmetric);
        result = 31 * result + Arrays.hashCode(scheme);
        result = 31 * result + Arrays.hashCode(kdf);
        return result;
    }
}
