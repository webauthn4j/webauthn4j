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
 * The supported attestation type(s). (e.g. ATTESTATION_BASIC_FULL(0x3E07), ATTESTATION_BASIC_SURROGATE(0x3E08)).
 *
 * @see <a href="https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-registry-v2.0-rd-20180702.html#authenticator-attestation-types">§3.6.3 Authenticator Attestation Types</a>
 */
public enum AttestationType {

    BASIC_FULL(0x3E07, "basic_full"),
    BASIC_SURROGATE(0x3E08, "basic_surrogate"),
    ECDAA(0x3E09, "ecdaa"),
    ATTCA(0x3E0A, "attca");

    private final int value;
    private final String string;

    AttestationType(int value, String string) {
        this.value = value;
        this.string = string;
    }

    public static AttestationType create(String value) {
        return Arrays.stream(AttestationType.values()).filter(item -> Objects.equals(item.string, value))
                .findFirst().orElseThrow(()->new IllegalArgumentException("value '" + value + "' is out of range"));
    }

    public static AttestationType create(int value) {
        if (value > UnsignedNumberUtil.UNSIGNED_SHORT_MAX || value < 0) {
            throw new IllegalArgumentException("value '" + value + "' is out of range");
        }
        return Arrays.stream(AttestationType.values()).filter(item -> item.value == value)
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
