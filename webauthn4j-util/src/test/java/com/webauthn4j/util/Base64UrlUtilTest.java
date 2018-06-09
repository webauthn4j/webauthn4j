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

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class Base64UrlUtilTest {

    @Test
    public void encode_test(){
        byte[] data = new byte[]{0x01, 0x23, 0x45};
        byte[] expected = new byte[]{0x41, 0x53, 0x4E, 0x46};
        byte[] result = Base64UrlUtil.encode(data);
        assertThat(result).isEqualTo(expected);
    }

    @Test
    public void decode_test(){
        byte[] data = new byte[]{0x41, 0x53, 0x4E, 0x46};
        byte[] expected = new byte[]{0x01, 0x23, 0x45};
        byte[] result = Base64UrlUtil.decode(data);
        assertThat(result).isEqualTo(expected);
    }
}
