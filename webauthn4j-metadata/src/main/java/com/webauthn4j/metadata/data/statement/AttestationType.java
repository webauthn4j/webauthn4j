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
 * The supported attestation type(s). (e.g. ATTESTATION_BASIC_FULL(0x3E07), ATTESTATION_BASIC_SURROGATE(0x3E08)).
 *
 * @see <a href="https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-registry-v2.0-rd-20180702.html#authenticator-attestation-types">§3.6.3 Authenticator Attestation Types</a>
 */
public enum AttestationType {

    BASIC_FULL(0x3E07),
    BASIC_SURROGATE(0x3E08),
    ECDAA(0x3E09),
    ATTCA(0x3E0A);

    private final int value;

    AttestationType(int value) {
        this.value = value;
    }

    public static AttestationType create(int value) {
        if (value > UnsignedNumberUtil.UNSIGNED_SHORT_MAX || value < 0) {
            throw new IllegalArgumentException("value '" + value + "' is out of range");
        }
        switch (value) {
            case 0x3E07:
                return BASIC_FULL;
            case 0x3E08:
                return BASIC_SURROGATE;
            case 0x3E09:
                return ECDAA;
            case 0x3E0A:
                return ATTCA;
            default:
                throw new IllegalArgumentException("value '" + value + "' is out of range");
        }
    }

    @JsonCreator
    private static AttestationType deserialize(int value) throws InvalidFormatException {
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
