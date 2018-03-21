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

package com.webauthn4j.webauthn.util;

import org.junit.Test;

import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test for CUnsignedNumberUtil
 */
public class UnsignedNumberUtilTest {

    @Test
    public void getUnsignedShort_test1() {
        byte[] bytes = new byte[4];
        bytes[0] = 0x00;
        bytes[1] = 0x01;
        long result = UnsignedNumberUtil.getUnsignedShort(ByteBuffer.wrap(bytes));
        assertThat(result).isEqualTo(1);
    }

    @Test
    public void getUnsignedShort_test2() {
        byte[] bytes = new byte[4];
        bytes[0] = (byte) 0xFF;
        bytes[1] = (byte) 0xFF;
        long result = UnsignedNumberUtil.getUnsignedShort(ByteBuffer.wrap(bytes));
        assertThat(result).isEqualTo(0xFFFFL);
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
        assertThat(result).isEqualTo(0xFFFFFFFFL);
    }

    @Test
    public void toBytes_test1() {
        byte[] bytes = UnsignedNumberUtil.toBytes(0x00000001L);
        assertThat(bytes).hasSize(4);
        assertThat(bytes).isEqualTo(new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01});
    }

    @Test
    public void toBytes_test2() {
        byte[] bytes = UnsignedNumberUtil.toBytes(0xFFFFFFFFL);
        assertThat(bytes).hasSize(4);
        assertThat(bytes).isEqualTo(new byte[]{(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF});
    }
}
