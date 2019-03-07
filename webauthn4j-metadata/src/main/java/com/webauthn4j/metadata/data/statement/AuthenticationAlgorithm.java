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
 * The supported authentication algorithm(s).
 * See section 3.6.1 Authentication Algorithms of FIDO Registry of Predefined Values
 */
public enum AuthenticationAlgorithm {

    ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW(0x0001),
    ALG_SIGN_SECP256R1_ECDSA_SHA256_DER(0x0002),
    ALG_SIGN_RSASSA_PSS_SHA256_RAW(0x0003),
    ALG_SIGN_RSASSA_PSS_SHA256_DER(0x0004),
    ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW(0x0005),
    ALG_SIGN_SECP256K1_ECDSA_SHA256_DER(0x0006),
    ALG_SIGN_SM2_SM3_RAW(0x0007),
    ALG_SIGN_RSA_EMSA_PKCS1_SHA256_RAW(0x0008),
    ALG_SIGN_RSA_EMSA_PKCS1_SHA256_DER(0x0009),
    ALG_SIGN_RSASSA_PSS_SHA384_RAW(0x000A),
    ALG_SIGN_RSASSA_PSS_SHA512_RAW(0x000B),
    ALG_SIGN_RSASSA_PKCSV15_SHA256_RAW(0x000C),
    ALG_SIGN_RSASSA_PKCSV15_SHA384_RAW(0x000D),
    ALG_SIGN_RSASSA_PKCSV15_SHA512_RAW(0x000E),
    ALG_SIGN_RSASSA_PKCSV15_SHA1_RAW(0x000F),
    ALG_SIGN_SECP384R1_ECDSA_SHA384_RAW(0x0010),
    ALG_SIGN_SECP521R1_ECDSA_SHA512_RAW(0x0011),
    ALG_SIGN_ED25519_EDDSA_SHA256_RAW(0x0012);

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
                return ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW;
            case 0x0002:
                return ALG_SIGN_SECP256R1_ECDSA_SHA256_DER;
            case 0x0003:
                return ALG_SIGN_RSASSA_PSS_SHA256_RAW;
            case 0x0004:
                return ALG_SIGN_RSASSA_PSS_SHA256_DER;
            case 0x0005:
                return ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW;
            case 0x0006:
                return ALG_SIGN_SECP256K1_ECDSA_SHA256_DER;
            case 0x0007:
                return ALG_SIGN_SM2_SM3_RAW;
            case 0x0008:
                return ALG_SIGN_RSA_EMSA_PKCS1_SHA256_RAW;
            case 0x0009:
                return ALG_SIGN_RSA_EMSA_PKCS1_SHA256_DER;
            case 0x000A:
                return ALG_SIGN_RSASSA_PSS_SHA384_RAW;
            case 0x000B:
                return ALG_SIGN_RSASSA_PSS_SHA512_RAW;
            case 0x000C:
                return ALG_SIGN_RSASSA_PKCSV15_SHA256_RAW;
            case 0x000D:
                return ALG_SIGN_RSASSA_PKCSV15_SHA384_RAW;
            case 0x000E:
                return ALG_SIGN_RSASSA_PKCSV15_SHA512_RAW;
            case 0x000F:
                return ALG_SIGN_RSASSA_PKCSV15_SHA1_RAW;
            case 0x0010:
                return ALG_SIGN_SECP384R1_ECDSA_SHA384_RAW;
            case 0x0011:
                return ALG_SIGN_SECP521R1_ECDSA_SHA512_RAW;
            case 0x0012:
                return ALG_SIGN_ED25519_EDDSA_SHA256_RAW;
            default:
                throw new IllegalArgumentException("value '" + value + "' is out of range");
        }
    }

    @JsonCreator
    private static AuthenticationAlgorithm fromJson(int value) throws InvalidFormatException {
        try{
            return create(value);
        }
        catch (IllegalArgumentException e){
            throw new InvalidFormatException(null, "value is out of range", value, AuthenticationAlgorithm.class);
        }
    }

    @JsonValue
    public int getValue() {
        return value;
    }
}
