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
import com.webauthn4j.util.UnsignedNumberUtil;

/**
 * The supported key protection type(s).
 * @see <a href="https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-registry-v2.0-rd-20180702.html#key-protection-types">§3.2 Key Protection Types</a>
 */
public enum  KeyProtection {

    SOFTWARE(0x0001),
    HARDWARE(0x0002),
    TEE(0x0004),
    SECURE_ELEMENT(0x0008),
    REMOTE_HANDLE(0x0010);

    private final int value;

    KeyProtection(int value) {
        this.value = value;
    }

    public static KeyProtection create(int value) {
        if (value > UnsignedNumberUtil.UNSIGNED_SHORT_MAX || value < 0) {
            throw new IllegalArgumentException("value '" + value + "' is out of range");
        }
        switch (value) {
            case 0x0001:
                return SOFTWARE;
            case 0x0002:
                return HARDWARE;
            case 0x0004:
                return TEE;
            case 0x0008:
                return SECURE_ELEMENT;
            case 0x0010:
                return REMOTE_HANDLE;
            default:
                throw new IllegalArgumentException("value '" + value + "' is out of range");
        }
    }

    @JsonCreator
    private static KeyProtection fromJson(int value) throws InvalidFormatException {
        try{
            return create(value);
        }
        catch (IllegalArgumentException e){
            throw new InvalidFormatException(null, "value is out of range", value, KeyProtection.class);
        }
    }

    @JsonValue
    public int getValue() {
        return value;
    }

}
