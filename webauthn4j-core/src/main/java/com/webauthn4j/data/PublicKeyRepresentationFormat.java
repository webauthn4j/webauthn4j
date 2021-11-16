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
 * The supported publik key representation format(s).
 *
 * @see <a href="https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-registry-v2.0-rd-20180702.html#public-key-representation-formats">§3.6.2 Public Key Representation Formats</a>
 */
public enum PublicKeyRepresentationFormat {

    ECC_X962_RAW(0x0100, "ecc_x962_raw"),
    ECC_X962_DER(0x0101, "ecc_x962_der"),
    RSA_2048_RAW(0x0102, "rsa_2048_raw"),
    RSA_2048_DER(0x0103, "rsa_2048_der"),
    COSE(0x0104, "cose");

    private static final String VALUE_OUT_OF_RANGE_TEMPLATE = "value %s is out of range";

    private final int value;
    private final String string;

    PublicKeyRepresentationFormat(int value, String string) {
        this.value = value;
        this.string = string;
    }

    public static PublicKeyRepresentationFormat create(int value) {
        if (value > UnsignedNumberUtil.UNSIGNED_SHORT_MAX || value < 0) {
            throw new IllegalArgumentException("value '" + value + "' is out of range");
        }
        return Arrays.stream(PublicKeyRepresentationFormat.values()).filter(item -> item.getValue() == value)
                .findFirst().orElseThrow(()->new IllegalArgumentException(String.format(VALUE_OUT_OF_RANGE_TEMPLATE, value)));
    }

    public static PublicKeyRepresentationFormat create(String value) {
        return Arrays.stream(PublicKeyRepresentationFormat.values()).filter(item -> Objects.equals(item.toString(), value))
                .findFirst().orElseThrow(()->new IllegalArgumentException(String.format(VALUE_OUT_OF_RANGE_TEMPLATE, value)));
    }

    public int getValue() {
        return value;
    }

    @Override
    public String toString(){
        return string;
    }
}

