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
import com.webauthn4j.util.UnsignedNumberUtil;

/**
 * The supported publik key representation format(s).
 *
 * @see <a href="https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-registry-v2.0-rd-20180702.html#public-key-representation-formats">§3.6.2 Public Key Representation Formats</a>
 */
public enum PublicKeyRepresentationFormat {

    ECC_X962_RAW(0x0100),
    ECC_X962_DER(0x0101),
    RSA_2048_RAW(0x0102),
    RSA_2048_DER(0x0103),
    COSE(0x0104);

    private final int value;

    PublicKeyRepresentationFormat(int value) {
        this.value = value;
    }

    public static PublicKeyRepresentationFormat create(int value) {
        if (value > UnsignedNumberUtil.UNSIGNED_SHORT_MAX || value < 0) {
            throw new IllegalArgumentException("value '" + value + "' is out of range");
        }
        switch (value) {
            case 0x0100:
                return ECC_X962_RAW;
            case 0x0101:
                return ECC_X962_DER;
            case 0x0102:
                return RSA_2048_RAW;
            case 0x0103:
                return RSA_2048_DER;
            case 0x0104:
                return COSE;
            default:
                throw new IllegalArgumentException("value '" + value + "' is out of range");
        }
    }

    @JsonCreator
    private static PublicKeyRepresentationFormat deserialize(int value) throws InvalidFormatException {
        try {
            return create(value);
        } catch (IllegalArgumentException e) {
            throw new InvalidFormatException(null, "value is out of range", value, AttestationType.class);
        }
    }

    @JsonValue
    public int getValue() {
        return value;
    }
}
