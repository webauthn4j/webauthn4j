/*
 * Copyright 2018 the original author or authors.
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
import com.webauthn4j.util.UnsignedNumberUtil;

import java.io.Serializable;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Objects;

public class TPMTHA implements Serializable {

    private TPMIAlgHash hashAlg;
    private byte[] digest;

    public TPMTHA(TPMIAlgHash hashAlg, byte[] digest) {
        this.hashAlg = hashAlg;
        this.digest = digest;
    }

    public TPMIAlgHash getHashAlg() {
        return hashAlg;
    }

    public byte[] getDigest() {
        return ArrayUtil.clone(digest);
    }

    public byte[] getBytes() {
        ByteBuffer buffer = ByteBuffer.allocate(2 + digest.length);
        buffer.put(UnsignedNumberUtil.toBytes(hashAlg.getValue()));
        buffer.put(digest);
        return buffer.array();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TPMTHA tpmtha = (TPMTHA) o;
        return hashAlg == tpmtha.hashAlg &&
                Arrays.equals(digest, tpmtha.digest);
    }

    @Override
    public int hashCode() {

        int result = Objects.hash(hashAlg);
        result = 31 * result + Arrays.hashCode(digest);
        return result;
    }
}
