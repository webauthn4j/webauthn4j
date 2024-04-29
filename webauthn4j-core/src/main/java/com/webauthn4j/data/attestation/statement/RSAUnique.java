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
import com.webauthn4j.util.UnsignedNumberUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class RSAUnique implements TPMUPublicId {

    private final byte[] n;

    public RSAUnique(@NotNull byte[] n) {
        this.n = n;
    }

    public @NotNull byte[] getN() {
        return ArrayUtil.clone(n);
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RSAUnique rsaUnique = (RSAUnique) o;
        return Arrays.equals(n, rsaUnique.n);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(n);
    }

    @Override
    public @NotNull byte[] getBytes() {
        ByteBuffer buffer = ByteBuffer.allocate(2 + n.length);
        buffer.put(UnsignedNumberUtil.toBytes(getN().length));
        buffer.put(getN());
        return buffer.array();
    }
}
