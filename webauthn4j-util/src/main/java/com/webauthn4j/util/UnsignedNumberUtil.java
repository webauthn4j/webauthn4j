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

package com.webauthn4j.util;

import java.math.BigInteger;
import java.nio.ByteBuffer;

/**
 * A Utility class for unsigned number
 */
public class UnsignedNumberUtil {

    public static final short UNSIGNED_BYTE_MAX = 0xFF;
    public static final int UNSIGNED_SHORT_MAX = 0xFFFF;
    public static final long UNSIGNED_INT_MAX = 0xFFFFFFFFL;
    public static final BigInteger UNSIGNED_LONG_MAX = new BigInteger("18446744073709551615");

    private static final String OUT_OF_RANGE_ERROR = "argument is out of range";

    private UnsignedNumberUtil() {
    }

    public static short getUnsignedByte(byte value) {
        return (short) Byte.toUnsignedInt(value);
    }

    public static int getUnsignedShort(ByteBuffer byteBuffer) {
        return Short.toUnsignedInt(byteBuffer.getShort());
    }

    public static int getUnsignedShort(byte[] bytes) {
        if (bytes.length != 2) {
            throw new IllegalArgumentException("byte array must be 2 bytes");
        }
        return getUnsignedShort(ByteBuffer.wrap(bytes));
    }

    public static long getUnsignedInt(ByteBuffer byteBuffer) {
        return Integer.toUnsignedLong(byteBuffer.getInt());
    }

    public static long getUnsignedInt(byte[] bytes) {
        if (bytes.length != 4) {
            throw new IllegalArgumentException("byte array must be 4 bytes");
        }
        return getUnsignedInt(ByteBuffer.wrap(bytes));
    }

    public static BigInteger getUnsignedLong(ByteBuffer byteBuffer) {
        byte[] buffer = new byte[8];
        byteBuffer.get(buffer);
        return new BigInteger(1, buffer);
    }

    public static byte[] toBytes(int ushortValue) {
        if (!isWithinUnsignedShort(ushortValue)) {
            throw new IllegalArgumentException(OUT_OF_RANGE_ERROR);
        }
        byte[] bytes = new byte[2];
        bytes[1] = (byte) (0x00ff & (ushortValue));
        bytes[0] = (byte) (0x00ff & (ushortValue >>> 8));
        return bytes;
    }

    public static byte[] toBytes(long uintValue) {
        if (!isWithinUnsignedInt(uintValue)) {
            throw new IllegalArgumentException(OUT_OF_RANGE_ERROR);
        }
        byte[] bytes = new byte[4];
        bytes[3] = (byte) (0x000000ff & (uintValue));
        bytes[2] = (byte) (0x000000ff & (uintValue >>> 8));
        bytes[1] = (byte) (0x000000ff & (uintValue >>> 16));
        bytes[0] = (byte) (0x000000ff & (uintValue >>> 24));
        return bytes;
    }

    public static byte[] toBytes(BigInteger unsignedLongValue) {
        if (!isWithinUnsignedLong(unsignedLongValue)) {
            throw new IllegalArgumentException(OUT_OF_RANGE_ERROR);
        }
        byte[] bytes = unsignedLongValue.toByteArray();
        byte[] buffer = new byte[8];
        int offset = (8 - bytes.length);
        for (int i = Math.max(0, offset); i < 8; i++) {
            buffer[i] = bytes[i - offset];
        }
        return buffer;
    }

    public static boolean isWithinUnsignedByte(int value) {
        return value <= UNSIGNED_BYTE_MAX && value >= 0;
    }

    public static boolean isWithinUnsignedShort(int value) {
        return value <= UNSIGNED_SHORT_MAX && value >= 0;
    }

    public static boolean isWithinUnsignedInt(long value) {
        return value <= UNSIGNED_INT_MAX && value >= 0;
    }

    public static boolean isWithinUnsignedLong(BigInteger value) {
        return value.bitLength() <= 64 && value.compareTo(BigInteger.valueOf(0)) >= 0;
    }

}
