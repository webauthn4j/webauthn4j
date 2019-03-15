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

package com.webauthn4j.data.attestation.statement;

import com.webauthn4j.util.ArrayUtil;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class TPMSRSAParms implements TPMUPublicParms {

    private byte[] symmetric;
    private byte[] scheme;
    private byte[] keyBits;
    private byte[] exponent;

    public TPMSRSAParms(byte[] symmetric, byte[] scheme, byte[] keyBits, byte[] exponent) {
        this.symmetric = symmetric;
        this.scheme = scheme;
        this.keyBits = keyBits;
        this.exponent = exponent;
    }

    public byte[] getSymmetric() {
        return ArrayUtil.clone(symmetric);
    }

    public byte[] getScheme() {
        return ArrayUtil.clone(scheme);
    }

    public byte[] getKeyBits() {
        return ArrayUtil.clone(keyBits);
    }

    public byte[] getExponent() {
        return ArrayUtil.clone(exponent);
    }

    public byte[] getBytes() {
        return ByteBuffer.allocate(10)
                .put(symmetric)
                .put(scheme)
                .put(keyBits)
                .put(exponent)
                .array();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TPMSRSAParms that = (TPMSRSAParms) o;
        return Arrays.equals(symmetric, that.symmetric) &&
                Arrays.equals(scheme, that.scheme) &&
                Arrays.equals(keyBits, that.keyBits) &&
                Arrays.equals(exponent, that.exponent);
    }

    @Override
    public int hashCode() {

        int result = Arrays.hashCode(symmetric);
        result = 31 * result + Arrays.hashCode(scheme);
        result = 31 * result + Arrays.hashCode(keyBits);
        result = 31 * result + Arrays.hashCode(exponent);
        return result;
    }
}
