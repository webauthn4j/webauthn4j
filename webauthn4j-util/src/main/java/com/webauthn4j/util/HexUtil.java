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


public class HexUtil {

    private static final String HEX_CHARS = "0123456789ABCDEF";
    private static final char[] HEX_CHAR_ARRAY = HEX_CHARS.toCharArray();

    private HexUtil() {
    }

    public static byte[] decode(String source) {
        source = source.toUpperCase();
        int sourceLength = source.length();
        if(sourceLength % 2 != 0){
            throw new IllegalArgumentException("source length must be even-length.");
        }
        byte[] bytes = new byte[sourceLength/2];
        char[] sourceChars = source.toCharArray();
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) ((HEX_CHARS.indexOf(sourceChars[i*2]) << 4) + HEX_CHARS.indexOf(sourceChars[i*2 + 1]));
        }

        return bytes;
    }

    public static String encodeToString(byte[] source) {
        StringBuilder stringBuilder = new StringBuilder(source.length * 2);
        for (byte item : source) {
            stringBuilder.append(HEX_CHAR_ARRAY[(item >> 4) & 0xF]);
            stringBuilder.append(HEX_CHAR_ARRAY[(item & 0xF)]);
        }
        return stringBuilder.toString();
    }

}
