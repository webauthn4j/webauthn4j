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

package com.webauthn4j.util;

import java.nio.ByteBuffer;

/**
 * A Utility class for unsigned number
 */
public class UnsignedNumberUtil {

    public static final short UNSIGNED_BYTE_MAX = 0xFF;
    public static final long  UNSIGNED_INT_MAX = 0xFFFFFFFFL;

    private UnsignedNumberUtil() {
    }

    public static int getUnsignedShort(ByteBuffer byteBuffer) {
        return (int) byteBuffer.getShort() & 0xffff;
    }

    public static long getUnsignedInt(ByteBuffer byteBuffer) {
        return (long) byteBuffer.getInt() & 0xffffffffL;
    }

    public static byte[] toBytes(int ushortValue) {
        byte[] bytes = new byte[2];
        bytes[1] = (byte) (0x00ff & (ushortValue));
        bytes[0] = (byte) (0x00ff & (ushortValue >>> 8));
        return bytes;
    }

    public static byte[] toBytes(long uintValue) {
        byte[] bytes = new byte[4];
        bytes[3] = (byte) (0x000000ff & (uintValue));
        bytes[2] = (byte) (0x000000ff & (uintValue >>> 8));
        bytes[1] = (byte) (0x000000ff & (uintValue >>> 16));
        bytes[0] = (byte) (0x000000ff & (uintValue >>> 24));
        return bytes;
    }


}
