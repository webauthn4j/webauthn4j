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

import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Test for CUnsignedNumberUtil
 */
public class UnsignedNumberUtilTest {

    @Test
    public void getUnsignedShort_test1() {
        byte[] bytes = new byte[4];
        bytes[0] = 0x00;
        bytes[1] = 0x01;
        int result = UnsignedNumberUtil.getUnsignedShort(ByteBuffer.wrap(bytes));
        assertThat(result).isEqualTo(1);
    }

    @Test
    public void getUnsignedShort_test2() {
        byte[] bytes = new byte[4];
        bytes[0] = (byte) 0xFF;
        bytes[1] = (byte) 0xFF;
        int result = UnsignedNumberUtil.getUnsignedShort(ByteBuffer.wrap(bytes));
        assertThat(result).isEqualTo(0x0000FFFF);
    }

    @Test
    public void getUnsignedShort_test3() {
        byte[] bytes = new byte[2];
        bytes[0] = 0x00;
        bytes[1] = 0x01;
        int result = UnsignedNumberUtil.getUnsignedShort(bytes);
        assertThat(result).isEqualTo(1);
    }

    @Test
    public void getUnsignedShort_test4() {
        byte[] bytes = new byte[4];
        assertThrows(IllegalArgumentException.class,
                () -> UnsignedNumberUtil.getUnsignedShort(bytes)
        );
    }

    @Test
    public void getUnsignedInt_test1() {
        byte[] bytes = new byte[4];
        bytes[0] = 0x00;
        bytes[1] = 0x00;
        bytes[2] = 0x00;
        bytes[3] = 0x01;
        long result = UnsignedNumberUtil.getUnsignedInt(ByteBuffer.wrap(bytes));
        assertThat(result).isEqualTo(1);
    }

    @Test
    public void getUnsignedInt_test2() {
        byte[] bytes = new byte[4];
        bytes[0] = (byte) 0xFF;
        bytes[1] = (byte) 0xFF;
        bytes[2] = (byte) 0xFF;
        bytes[3] = (byte) 0xFF;
        long result = UnsignedNumberUtil.getUnsignedInt(ByteBuffer.wrap(bytes));
        assertThat(result).isEqualTo(0x00000000FFFFFFFFL);
    }

    @Test
    public void getUnsignedInt_test3() {
        byte[] bytes = new byte[4];
        bytes[0] = (byte) 0xFF;
        bytes[1] = (byte) 0xFF;
        bytes[2] = (byte) 0xFF;
        bytes[3] = (byte) 0xFF;
        long result = UnsignedNumberUtil.getUnsignedInt(bytes);
        assertThat(result).isEqualTo(0x00000000FFFFFFFFL);
    }

    @Test
    public void getUnsignedInt_test4() {
        byte[] bytes = new byte[8];
        assertThrows(IllegalArgumentException.class,
                () -> UnsignedNumberUtil.getUnsignedInt(bytes)
        );
    }

    @Test
    public void toBytes_test1() {
        assertThrows(IllegalArgumentException.class,
                () -> UnsignedNumberUtil.toBytes((short) -1)
        );
    }

    @Test
    public void toBytes_test2() {
        assertThrows(IllegalArgumentException.class,
                () -> UnsignedNumberUtil.toBytes(-1)
        );
    }

    @Test
    public void toBytes_test3() {
        assertThrows(IllegalArgumentException.class,
                () -> UnsignedNumberUtil.toBytes((long) -1)
        );
    }

    @Test
    public void toBytes_test4() {
        assertThrows(IllegalArgumentException.class,
                () -> UnsignedNumberUtil.toBytes(BigInteger.valueOf(-1))
        );
    }

    @Test
    public void getUnsignedLong_form_UNSIGNED_LONG_MAX_test() {
        byte[] bytes = new byte[8];
        bytes[0] = (byte) 0xFF;
        bytes[1] = (byte) 0xFF;
        bytes[2] = (byte) 0xFF;
        bytes[3] = (byte) 0xFF;
        bytes[4] = (byte) 0xFF;
        bytes[5] = (byte) 0xFF;
        bytes[6] = (byte) 0xFF;
        bytes[7] = (byte) 0xFF;
        assertThat(UnsignedNumberUtil.getUnsignedLong(ByteBuffer.wrap(bytes))).isEqualTo(UnsignedNumberUtil.UNSIGNED_LONG_MAX);
    }

    @Test
    public void toBytes_long_1_test1() {
        byte[] bytes = UnsignedNumberUtil.toBytes(0x00000001L);
        assertAll(
                () -> assertThat(bytes).hasSize(4),
                () -> assertThat(bytes).isEqualTo(new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01})
        );
    }

    @Test
    public void toBytes_long_uint_max_test2() {
        byte[] bytes = UnsignedNumberUtil.toBytes(0xFFFFFFFFL);
        assertAll(
                () -> assertThat(bytes).hasSize(4),
                () -> assertThat(bytes).isEqualTo(new byte[]{(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF})
        );
    }

    @Test
    public void toBytes_ulong_max_test() {
        byte[] bytes = UnsignedNumberUtil.toBytes(UnsignedNumberUtil.UNSIGNED_LONG_MAX);
        assertThat(bytes).isEqualTo(new byte[]{(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF});
    }

    @Test
    public void toBytes_BigInteger_uint_max_test() {
        byte[] bytes = UnsignedNumberUtil.toBytes(BigInteger.valueOf(UnsignedNumberUtil.UNSIGNED_INT_MAX));
        assertThat(bytes).isEqualTo(new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF});
    }

    @Test
    public void isWithinUnsignedLong_test() {
        assertAll(
                () -> assertThat(UnsignedNumberUtil.isWithinUnsignedLong(UnsignedNumberUtil.UNSIGNED_LONG_MAX)).isTrue(),
                () -> assertThat(UnsignedNumberUtil.isWithinUnsignedLong(BigInteger.valueOf(0))).isTrue(),
                () -> assertThat(UnsignedNumberUtil.isWithinUnsignedLong(new BigInteger("18446744073709551616"))).isFalse(),
                () -> assertThat(UnsignedNumberUtil.isWithinUnsignedLong(BigInteger.valueOf(-1))).isFalse()
        );
    }
}
