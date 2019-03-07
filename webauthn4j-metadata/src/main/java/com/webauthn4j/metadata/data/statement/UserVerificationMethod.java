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
package com.webauthn4j.metadata.data.statement;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;

/**
 * The supported user verification method(s).
 * See section 3.1 User Verification Methods of FIDO FIDO Registry of Predefined Values.
 */
public enum UserVerificationMethod {

    USER_VERIFY_PRESENCE(0x00000001L),
    USER_VERIFY_FINGERPRINT(0x00000002L),
    USER_VERIFY_PASSCODE(0x00000004L),
    USER_VERIFY_VOICEPRINT(0x00000008L),
    USER_VERIFY_FACEPRINT(0x00000010L),
    USER_VERIFY_LOCATION(0x00000020L),
    USER_VERIFY_EYEPRINT(0x00000040L),
    USER_VERIFY_PATTERN(0x00000080L),
    USER_VERIFY_HANDPRINT(0x00000100L),
    USER_VERIFY_NONE(0x00000200L),
    USER_VERIFY_ALL(0x00000400L);

    private final long value;

    UserVerificationMethod(long value) {
        this.value = value;
    }

    public static UserVerificationMethod create(long value) {
        if (value == 0x00000001L) {
            return USER_VERIFY_PRESENCE;
        } else if (value == 0x00000002L) {
            return USER_VERIFY_FINGERPRINT;
        } else if (value == 0x00000004L) {
            return USER_VERIFY_PASSCODE;
        } else if (value == 0x00000008L) {
            return USER_VERIFY_VOICEPRINT;
        } else if (value == 0x00000010L) {
            return USER_VERIFY_FACEPRINT;
        } else if (value == 0x00000020L) {
            return USER_VERIFY_LOCATION;
        } else if (value == 0x00000040L) {
            return USER_VERIFY_EYEPRINT;
        } else if (value == 0x00000080L) {
            return USER_VERIFY_PATTERN;
        } else if (value == 0x00000100L) {
            return USER_VERIFY_HANDPRINT;
        } else if (value == 0x00000200L) {
            return USER_VERIFY_NONE;
        } else if (value == 0x00000400L) {
            return USER_VERIFY_ALL;
        } else {
            throw new IllegalArgumentException("value '" + value + "' is out of range");
        }
    }

    @JsonCreator
    private static UserVerificationMethod fromJson(long value) throws InvalidFormatException {
        try{
            return create(value);
        }
        catch (IllegalArgumentException e){
            throw new InvalidFormatException(null, "value is out of range", value, UserVerificationMethod.class);
        }
    }

    @JsonValue
    public long getValue() {
        return value;
    }
}
