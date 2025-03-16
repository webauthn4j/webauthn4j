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

package com.webauthn4j.util;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.math.BigInteger;

public class ArrayUtil {

    private ArrayUtil() {
    }

    public static @Nullable
    byte[] clone(@Nullable byte[] value) {
        return value == null ? null : value.clone();
    }

    public static @Nullable String[] clone(@Nullable String[] value) {
        return value == null ? null : value.clone();
    }

    public static @Nullable String toHexString(@Nullable byte[] value){
        return value == null ? null : HexUtil.encodeToString(value);
    }

    public static @NotNull byte[] convertToFixedByteArray(@NotNull BigInteger value) {
        return convertToFixedByteArray(32, value);
    }

    public static @NotNull byte[] convertToFixedByteArray(int fixedSize, @NotNull BigInteger value) {
        byte[] bytes = value.toByteArray();

        byte[] adjusted = new byte[fixedSize];
        if (bytes.length <= fixedSize) {
            System.arraycopy(bytes, 0, adjusted, fixedSize - bytes.length, bytes.length);
        }
        else if (bytes.length == fixedSize + 1 && bytes[0] == 0) {
            System.arraycopy(bytes, 1, adjusted, 0, fixedSize);
        }
        else {
            throw new IllegalStateException("Value is too large, fixedSize: " + fixedSize + ", array size: " + bytes.length + ", starts with 0: " + (bytes[0] == 0 ? "yes" : "no"));
        }
        return adjusted;
    }
}
