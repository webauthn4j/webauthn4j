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
package com.webauthn4j.metadata.data.statement;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;

/**
 * The supported user verification method(s).
 *
 * @see <a href="https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-registry-v2.0-rd-20180702.html#user-verification-methods">§3.1 User Verification Methods</a>
 */
public enum UserVerificationMethod {

    PRESENCE(0x00000001L),
    FINGERPRINT(0x00000002L),
    PASSCODE(0x00000004L),
    VOICEPRINT(0x00000008L),
    FACEPRINT(0x00000010L),
    LOCATION(0x00000020L),
    EYEPRINT(0x00000040L),
    PATTERN(0x00000080L),
    HANDPRINT(0x00000100L),
    NONE(0x00000200L),
    ALL(0x00000400L);

    private final long value;

    UserVerificationMethod(long value) {
        this.value = value;
    }

    public static UserVerificationMethod create(long value) {
        if (value == 0x00000001L) {
            return PRESENCE;
        } else if (value == 0x00000002L) {
            return FINGERPRINT;
        } else if (value == 0x00000004L) {
            return PASSCODE;
        } else if (value == 0x00000008L) {
            return VOICEPRINT;
        } else if (value == 0x00000010L) {
            return FACEPRINT;
        } else if (value == 0x00000020L) {
            return LOCATION;
        } else if (value == 0x00000040L) {
            return EYEPRINT;
        } else if (value == 0x00000080L) {
            return PATTERN;
        } else if (value == 0x00000100L) {
            return HANDPRINT;
        } else if (value == 0x00000200L) {
            return NONE;
        } else if (value == 0x00000400L) {
            return ALL;
        } else {
            throw new IllegalArgumentException("value '" + value + "' is out of range");
        }
    }

    @JsonCreator
    private static UserVerificationMethod deserialize(long value) throws InvalidFormatException {
        try {
            return create(value);
        } catch (IllegalArgumentException e) {
            throw new InvalidFormatException(null, "value is out of range", value, UserVerificationMethod.class);
        }
    }

    @JsonValue
    public long getValue() {
        return value;
    }
}
