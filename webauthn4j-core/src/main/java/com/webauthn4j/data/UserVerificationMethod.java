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
import org.checkerframework.checker.nullness.qual.NonNull;

/**
 * The supported user verification method(s).
 *
 * @see <a href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#user-verification-methods">§3.1 User Verification Methods</a>
 */
public enum UserVerificationMethod {

    PRESENCE_INTERNAL(0x00000001L),
    FINGERPRINT_INTERNAL(0x00000002L),
    PASSCODE_INTERNAL(0x00000004L),
    VOICEPRINT_INTERNAL(0x00000008L),
    FACEPRINT_INTERNAL(0x00000010L),
    LOCATION_INTERNAL(0x00000020L),
    EYEPRINT_INTERNAL(0x00000040L),
    PATTERN_INTERNAL(0x00000080L),
    HANDPRINT_INTERNAL(0x00000100L),
    PASSCODE_EXTERNAL(0x00000800L),
    PATTERN_EXTERNAL(0x00001000L),
    NONE(0x00000200L),
    ALL(0x00000400L);

    private final long value;

    UserVerificationMethod(long value) {
        this.value = value;
    }

    public static UserVerificationMethod create(long value) {
        if (value == 0x00000001L) {
            return PRESENCE_INTERNAL;
        }
        else if (value == 0x00000002L) {
            return FINGERPRINT_INTERNAL;
        }
        else if (value == 0x00000004L) {
            return PASSCODE_INTERNAL;
        }
        else if (value == 0x00000008L) {
            return VOICEPRINT_INTERNAL;
        }
        else if (value == 0x00000010L) {
            return FACEPRINT_INTERNAL;
        }
        else if (value == 0x00000020L) {
            return LOCATION_INTERNAL;
        }
        else if (value == 0x00000040L) {
            return EYEPRINT_INTERNAL;
        }
        else if (value == 0x00000080L) {
            return PATTERN_INTERNAL;
        }
        else if (value == 0x00000100L) {
            return HANDPRINT_INTERNAL;
        }
        else if (value == 0x00000800L) {
            return PASSCODE_EXTERNAL;
        }
        else if (value == 0x00001000L) {
            return PATTERN_EXTERNAL;
        }
        else if (value == 0x00000200L) {
            return NONE;
        }
        else if (value == 0x00000400L) {
            return ALL;
        }
        else {
            throw new IllegalArgumentException("value '" + value + "' is out of range");
        }
    }

    @SuppressWarnings("unused")
    @JsonCreator
    private static @NonNull UserVerificationMethod deserialize(long value) throws InvalidFormatException {
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

    @Override
    public String toString() {
        switch (this){
            case PRESENCE_INTERNAL:
                return "PRESENCE_INTERNAL";
            case FINGERPRINT_INTERNAL:
                return "FINGERPRINT_INTERNAL";
            case PASSCODE_INTERNAL:
                return "PASSCODE_INTERNAL";
            case VOICEPRINT_INTERNAL:
                return "VOICEPRINT_INTERNAL";
            case FACEPRINT_INTERNAL:
                return "FACEPRINT_INTERNAL";
            case LOCATION_INTERNAL:
                return "LOCATION_INTERNAL";
            case EYEPRINT_INTERNAL:
                return "EYEPRINT_INTERNAL";
            case PATTERN_INTERNAL:
                return "PATTERN_INTERNAL";
            case HANDPRINT_INTERNAL:
                return "HANDPRINT_INTERNAL";
            case PASSCODE_EXTERNAL:
                return "PASSCODE_EXTERNAL";
            case PATTERN_EXTERNAL:
                return "PATTERN_EXTERNAL";
            case NONE:
                return "NONE";
            case ALL:
                return "ALL";
            default:
                return String.format("UNKNOWN(%08X)", value);
        }
    }
}
