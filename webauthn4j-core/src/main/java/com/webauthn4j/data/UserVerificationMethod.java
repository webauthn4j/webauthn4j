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

import com.fasterxml.jackson.annotation.JsonValue;
import com.webauthn4j.util.UnsignedNumberUtil;

import java.util.Arrays;
import java.util.Objects;

/**
 * The supported user verification method(s).
 *
 * @see <a href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#user-verification-methods">§3.1 User Verification Methods</a>
 */
public enum UserVerificationMethod {

    PRESENCE_INTERNAL(0x00000001L, "presence_internal"),
    FINGERPRINT_INTERNAL(0x00000002L, "fingerprint_internal"),
    PASSCODE_INTERNAL(0x00000004L, "passcode_internal"),
    VOICEPRINT_INTERNAL(0x00000008L, "voiceprint_internal"),
    FACEPRINT_INTERNAL(0x00000010L, "faceprint_internal"),
    LOCATION_INTERNAL(0x00000020L, "location_internal"),
    EYEPRINT_INTERNAL(0x00000040L, "eyeprint_internal"),
    PATTERN_INTERNAL(0x00000080L, "pattern_internal"),
    HANDPRINT_INTERNAL(0x00000100L, "handprint_internal"),
    PASSCODE_EXTERNAL(0x00000800L, "passcode_external"),
    PATTERN_EXTERNAL(0x00001000L, "pattern_external"),
    NONE(0x00000200L, "none"),
    ALL(0x00000400L, "all");

    private static final String VALUE_OUT_OF_RANGE_TEMPLATE = "value %s is out of range";

    private final long value;
    private final String string;

    UserVerificationMethod(long value, String string) {
        this.value = value;
        this.string = string;
    }

    public static UserVerificationMethod create(String value) {
        return Arrays.stream(UserVerificationMethod.values()).filter(item -> Objects.equals(item.string, value))
                .findFirst().orElseThrow(()->new IllegalArgumentException(String.format(VALUE_OUT_OF_RANGE_TEMPLATE, value)));
    }

    public static UserVerificationMethod create(long value) {
        if (value > UnsignedNumberUtil.UNSIGNED_INT_MAX || value < 0) {
            throw new IllegalArgumentException(String.format(VALUE_OUT_OF_RANGE_TEMPLATE, value));
        }
        return Arrays.stream(UserVerificationMethod.values()).filter(item -> item.value == value)
                .findFirst().orElseThrow(()->new IllegalArgumentException(String.format(VALUE_OUT_OF_RANGE_TEMPLATE, value)));
    }

    @JsonValue
    public long getValue() {
        return value;
    }

    @Override
    public String toString(){
        return string;
    }
}
