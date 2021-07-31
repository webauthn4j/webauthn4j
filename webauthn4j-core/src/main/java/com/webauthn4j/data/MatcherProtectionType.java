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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import com.webauthn4j.util.UnsignedNumberUtil;
import org.checkerframework.checker.nullness.qual.NonNull;

/**
 * The supported matcher protection type(s).
 *
 * @see <a href="https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-registry-v2.0-rd-20180702.html#matcher-protection-types">§3.3 Matcher Protection Types</a>
 */
public enum MatcherProtectionType {

    SOFTWARE(0x0001),
    TEE(0x0002),
    ON_CHIP(0x0004);

    private final int value;

    MatcherProtectionType(int value) {
        this.value = value;
    }

    public static @NonNull MatcherProtectionType create(int value) {
        if (value > UnsignedNumberUtil.UNSIGNED_SHORT_MAX || value < 0) {
            throw new IllegalArgumentException("value '" + value + "' is out of range");
        }
        switch (value) {
            case 0x0001:
                return SOFTWARE;
            case 0x0002:
                return TEE;
            case 0x0004:
                return ON_CHIP;
            default:
                throw new IllegalArgumentException("value '" + value + "' is out of range");
        }
    }

    @SuppressWarnings("unused")
    @JsonCreator
    private static @NonNull MatcherProtectionType deserialize(int value) throws InvalidFormatException {
        try {
            return create(value);
        } catch (IllegalArgumentException e) {
            throw new InvalidFormatException(null, "value is out of range", value, MatcherProtectionType.class);
        }
    }

    @JsonValue
    public int getValue() {
        return value;
    }

    @Override
    public String toString() {
        switch (value){
            case 0x0001:
                return "SOFTWARE";
            case 0x0002:
                return "TEE";
            case 0x0004:
                return "ON_CHIP";
            default:
                return "UNKNOWN(" + String.format("%04X", value) + ")";
        }
    }
}
