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

package com.webauthn4j.data;

import com.webauthn4j.util.UnsignedNumberUtil;

import java.util.Arrays;
import java.util.Objects;

/**
 * The supported key protection type(s).
 *
 * @see <a href="https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-registry-v2.0-rd-20180702.html#key-protection-types">§3.2 Key Protection Types</a>
 */
public enum KeyProtectionType {

    SOFTWARE(0x0001, "software"),
    HARDWARE(0x0002, "hardware"),
    TEE(0x0004, "tee"),
    SECURE_ELEMENT(0x0008, "secure_element"),
    REMOTE_HANDLE(0x0010, "remote_handle");

    private static final String VALUE_OUT_OF_RANGE_TEMPLATE = "value %s is out of range";

    private final int value;
    private final String string;

    KeyProtectionType(int value, String string) {
        this.value = value;
        this.string = string;
    }

    public static KeyProtectionType create(String value) {
        return Arrays.stream(KeyProtectionType.values()).filter(item -> Objects.equals(item.string, value))
                .findFirst().orElseThrow(()->new IllegalArgumentException(String.format(VALUE_OUT_OF_RANGE_TEMPLATE, value)));
    }

    public static KeyProtectionType create(int value) {
        if (value > UnsignedNumberUtil.UNSIGNED_SHORT_MAX || value < 0) {
            throw new IllegalArgumentException(String.format(VALUE_OUT_OF_RANGE_TEMPLATE, value));
        }
        return Arrays.stream(KeyProtectionType.values()).filter(item -> item.value == value)
                .findFirst().orElseThrow(()->new IllegalArgumentException(String.format(VALUE_OUT_OF_RANGE_TEMPLATE, value)));
    }

    public int getValue() {
        return value;
    }

    @Override
    public String toString(){
        return string;
    }
}
