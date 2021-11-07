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
 * The supported matcher protection type(s).
 *
 * @see <a href="https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-registry-v2.0-rd-20180702.html#matcher-protection-types">§3.3 Matcher Protection Types</a>
 */
public enum MatcherProtectionType {

    SOFTWARE(0x0001, "software"),
    TEE(0x0002, "tee"),
    ON_CHIP(0x0004, "on_chip");

    private final int value;
    private final String string;

    MatcherProtectionType(int value, String string) {
        this.value = value;
        this.string = string;
    }

    public static MatcherProtectionType create(String value) {
        return Arrays.stream(MatcherProtectionType.values()).filter(item -> Objects.equals(item.string, value))
                .findFirst().orElseThrow(()->new IllegalArgumentException("value '" + value + "' is out of range"));
    }

    public static MatcherProtectionType create(int value) {
        if (value > UnsignedNumberUtil.UNSIGNED_SHORT_MAX || value < 0) {
            throw new IllegalArgumentException("value '" + value + "' is out of range");
        }
        return Arrays.stream(MatcherProtectionType.values()).filter(item -> item.value == value)
                .findFirst().orElseThrow(()->new IllegalArgumentException("value '" + value + "' is out of range"));
    }

    public int getValue() {
        return value;
    }

    @Override
    public String toString(){
        return string;
    }
}
