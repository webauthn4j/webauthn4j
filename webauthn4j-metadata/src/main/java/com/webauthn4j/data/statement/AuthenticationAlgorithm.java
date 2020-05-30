/*
 * Copyright 2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webauthn4j.data.statement;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import com.webauthn4j.util.UnsignedNumberUtil;

/**
 * The supported authentication algorithm(s).
 *
 * @see <a href="https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-registry-v2.0-rd-20180702.html#authentication-algorithms">§3.6.1 Authentication Algorithms</a>
 */
public enum AuthenticationAlgorithm {

    SECP256R1_ECDSA_SHA256_RAW(0x0001),
    SECP256R1_ECDSA_SHA256_DER(0x0002),
    RSASSA_PSS_SHA256_RAW(0x0003),
    RSASSA_PSS_SHA256_DER(0x0004),
    SECP256K1_ECDSA_SHA256_RAW(0x0005),
    SECP256K1_ECDSA_SHA256_DER(0x0006),
    SM2_SM3_RAW(0x0007),
    RSA_EMSA_PKCS1_SHA256_RAW(0x0008),
    RSA_EMSA_PKCS1_SHA256_DER(0x0009),
    RSASSA_PSS_SHA384_RAW(0x000A),
    RSASSA_PSS_SHA512_RAW(0x000B),
    RSASSA_PKCSV15_SHA256_RAW(0x000C),
    RSASSA_PKCSV15_SHA384_RAW(0x000D),
    RSASSA_PKCSV15_SHA512_RAW(0x000E),
    RSASSA_PKCSV15_SHA1_RAW(0x000F),
    SECP384R1_ECDSA_SHA384_RAW(0x0010),
    SECP521R1_ECDSA_SHA512_RAW(0x0011),
    ED25519_EDDSA_SHA256_RAW(0x0012);

    private final int value;

    AuthenticationAlgorithm(int value) {
        this.value = value;
    }

    public static AuthenticationAlgorithm create(int value) {
        if (value > UnsignedNumberUtil.UNSIGNED_SHORT_MAX || value < 0) {
            throw new IllegalArgumentException("value '" + value + "' is out of range");
        }
        switch (value) {
            case 0x0001:
                return SECP256R1_ECDSA_SHA256_RAW;
            case 0x0002:
                return SECP256R1_ECDSA_SHA256_DER;
            case 0x0003:
                return RSASSA_PSS_SHA256_RAW;
            case 0x0004:
                return RSASSA_PSS_SHA256_DER;
            case 0x0005:
                return SECP256K1_ECDSA_SHA256_RAW;
            case 0x0006:
                return SECP256K1_ECDSA_SHA256_DER;
            case 0x0007:
                return SM2_SM3_RAW;
            case 0x0008:
                return RSA_EMSA_PKCS1_SHA256_RAW;
            case 0x0009:
                return RSA_EMSA_PKCS1_SHA256_DER;
            case 0x000A:
                return RSASSA_PSS_SHA384_RAW;
            case 0x000B:
                return RSASSA_PSS_SHA512_RAW;
            case 0x000C:
                return RSASSA_PKCSV15_SHA256_RAW;
            case 0x000D:
                return RSASSA_PKCSV15_SHA384_RAW;
            case 0x000E:
                return RSASSA_PKCSV15_SHA512_RAW;
            case 0x000F:
                return RSASSA_PKCSV15_SHA1_RAW;
            case 0x0010:
                return SECP384R1_ECDSA_SHA384_RAW;
            case 0x0011:
                return SECP521R1_ECDSA_SHA512_RAW;
            case 0x0012:
                return ED25519_EDDSA_SHA256_RAW;
            default:
                throw new IllegalArgumentException("value '" + value + "' is out of range");
        }
    }

    @JsonCreator
    private static AuthenticationAlgorithm deserialize(int value) throws InvalidFormatException {
        try {
            return create(value);
        } catch (IllegalArgumentException e) {
            throw new InvalidFormatException(null, "value is out of range", value, AuthenticationAlgorithm.class);
        }
    }

    @JsonValue
    public int getValue() {
        return value;
    }
}
