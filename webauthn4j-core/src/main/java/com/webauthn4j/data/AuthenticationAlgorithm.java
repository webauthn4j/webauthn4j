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
 * The supported authentication algorithm(s).
 *
 * @see <a href="https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-registry-v2.0-rd-20180702.html#authentication-algorithms">§3.6.1 Authentication Algorithms</a>
 */
public enum AuthenticationAlgorithm {

    SECP256R1_ECDSA_SHA256_RAW(0x0001, "secp256r1_ecdsa_sha256_raw"),
    SECP256R1_ECDSA_SHA256_DER(0x0002, "secp256r1_ecdsa_sha256_der"),
    RSASSA_PSS_SHA256_RAW(0x0003, "rsassa_pss_sha256_raw"),
    RSASSA_PSS_SHA256_DER(0x0004, "rsassa_pss_sha256_der"),
    SECP256K1_ECDSA_SHA256_RAW(0x0005, "secp256k1_ecdsa_sha256_raw"),
    SECP256K1_ECDSA_SHA256_DER(0x0006, "secp256k1_ecdsa_sha256_der"),
    SM2_SM3_RAW(0x0007, "sm2_sm3_raw"),
    RSA_EMSA_PKCS1_SHA256_RAW(0x0008, "rsa_emsa_pkcs1_sha256_raw"),
    RSA_EMSA_PKCS1_SHA256_DER(0x0009, "rsa_emsa_pkcs1_sha256_der"),
    RSASSA_PSS_SHA384_RAW(0x000A, "rsassa_pss_sha384_raw"),
    RSASSA_PSS_SHA512_RAW(0x000B, "rsassa_pss_sha512_raw"),
    RSASSA_PKCSV15_SHA256_RAW(0x000C, "rsassa_pkcsv15_sha256_raw"),
    RSASSA_PKCSV15_SHA384_RAW(0x000D, "rsassa_pkcsv15_sha384_raw"),
    RSASSA_PKCSV15_SHA512_RAW(0x000E, "rsassa_pkcsv15_sha512_raw"),
    RSASSA_PKCSV15_SHA1_RAW(0x000F, "rsassa_pkcsv15_sha1_raw"),
    SECP384R1_ECDSA_SHA384_RAW(0x0010, "secp384r1_ecdsa_sha384_raw"),
    SECP521R1_ECDSA_SHA512_RAW(0x0011, "secp512r1_ecdsa_sha512_raw"),
    ED25519_EDDSA_SHA512_RAW(0x0012, "ed25519_eddsa_sha512_raw");

    private static final String VALUE_OUT_OF_RANGE_TEMPLATE = "value %s is out of range";

    private final int value;
    private final String string;

    AuthenticationAlgorithm(int value, String string) {

        this.value = value;
        this.string = string;
    }

    public static AuthenticationAlgorithm create(int value) {
        if (value > UnsignedNumberUtil.UNSIGNED_SHORT_MAX || value < 0) {
            throw new IllegalArgumentException(String.format(VALUE_OUT_OF_RANGE_TEMPLATE, value));
        }
        return Arrays.stream(AuthenticationAlgorithm.values()).filter(item -> item.value == value)
                .findFirst().orElseThrow(()->new IllegalArgumentException(String.format(VALUE_OUT_OF_RANGE_TEMPLATE, value)));
    }

    public static AuthenticationAlgorithm create(String value) {
        return Arrays.stream(AuthenticationAlgorithm.values()).filter(item -> Objects.equals(item.string, value))
                .findFirst().orElseThrow(()->new IllegalArgumentException(String.format(VALUE_OUT_OF_RANGE_TEMPLATE, value)));
    }

    public int getValue() {
        return value;
    }

    @Override
    public String toString() {
        return string;
    }
}
