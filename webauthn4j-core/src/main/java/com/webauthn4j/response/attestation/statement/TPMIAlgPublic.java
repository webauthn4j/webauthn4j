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

package com.webauthn4j.response.attestation.statement;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;

public enum  TPMIAlgPublic {
    TPM_ALG_ERROR(0),
    TPM_ALG_RSA(1),
    TPM_ALG_SHA1(4),
    TPM_ALG_HMAC(5),
    TPM_ALG_AES(6),
    TPM_ALG_MGF1(7),
    TPM_ALG_KEYEDHASH(8),
    TPM_ALG_XOR(0x0A),
    TPM_ALG_SHA256(0x0B),
    TPM_ALG_SHA384(0x0C),
    TPM_ALG_SHA512(0xD),
    TPM_ALG_NULL(0x10),
    TPM_ALG_SM3_256(0x12),
    TPM_ALG_SM4(0x13),
    TPM_ALG_RSASSA(0x14),
    TPM_ALG_RSAES(0x15),
    TPM_ALG_RSAPSS(0x16),
    TPM_ALG_OAEP(0x17),
    TPM_ALG_ECDSA(0x18),
    TPM_ALG_ECDH(0x19),
    TPM_ALG_ECDAA(0x1A),
    TPM_ALG_SM2(0x1B),
    TPM_ALG_ECSCHNORR(0x1C),
    TPM_ALG_ECMQV(0x1D),
    TPM_ALG_KDF1_SP800_56A(0x20),
    TPM_ALG_KDF2(0x21),
    TPM_ALG_KDF1_SP800_108(0x22),
    TPM_ALG_ECC(0x23),
    TPM_ALG_SYMCIPHER(0x25),
    TPM_ALG_CAMELLIA(0x26),
    TPM_ALG_CTR(0x40),
    TPM_ALG_OFB(0x41),
    TPM_ALG_CBC(0x42),
    TPM_ALG_CFB(0x43),
    TPM_ALG_ECB(0x44);

    private final int value;

    TPMIAlgPublic(int value) {
        this.value = value;
    }

    @JsonCreator
    public static TPMIAlgPublic create(int value) throws InvalidFormatException {
        if (value == TPM_ALG_ERROR.value) {
            return TPM_ALG_ERROR;
        } else if (value == TPM_ALG_RSA.value) {
            return TPM_ALG_RSA;
        } else if (value == TPM_ALG_SHA1.value) {
            return TPM_ALG_SHA1;
        } else if (value == TPM_ALG_HMAC.value) {
            return TPM_ALG_HMAC;
        } else if (value == TPM_ALG_AES.value) {
            return TPM_ALG_AES;
        } else if (value == TPM_ALG_MGF1.value) {
            return TPM_ALG_MGF1;
        } else if (value == TPM_ALG_KEYEDHASH.value) {
            return TPM_ALG_KEYEDHASH;
        } else if (value == TPM_ALG_XOR.value) {
            return TPM_ALG_XOR;
        } else if (value == TPM_ALG_SHA256.value) {
            return TPM_ALG_SHA256;
        } else if (value == TPM_ALG_SHA384.value) {
            return TPM_ALG_SHA384;
        } else if (value == TPM_ALG_SHA512.value) {
            return TPM_ALG_SHA512;
        } else if (value == TPM_ALG_NULL.value) {
            return TPM_ALG_NULL;
        } else if (value == TPM_ALG_SM3_256.value) {
            return TPM_ALG_SM3_256;
        } else if (value == TPM_ALG_SM4.value) {
            return TPM_ALG_SM4;
        } else if (value == TPM_ALG_RSASSA.value) {
            return TPM_ALG_RSASSA;
        } else if (value == TPM_ALG_RSAES.value) {
            return TPM_ALG_RSAES;
        } else if (value == TPM_ALG_RSAPSS.value) {
            return TPM_ALG_RSAPSS;
        } else if (value == TPM_ALG_OAEP.value) {
            return TPM_ALG_OAEP;
        } else if (value == TPM_ALG_ECDSA.value) {
            return TPM_ALG_ECDSA;
        } else if (value == TPM_ALG_ECDH.value) {
            return TPM_ALG_ECDH;
        } else if (value == TPM_ALG_ECDAA.value) {
            return TPM_ALG_ECDAA;
        } else if (value == TPM_ALG_SM2.value) {
            return TPM_ALG_SM2;
        } else if (value == TPM_ALG_ECSCHNORR.value) {
            return TPM_ALG_ECSCHNORR;
        } else if (value == TPM_ALG_ECMQV.value) {
            return TPM_ALG_ECMQV;
        } else if (value == TPM_ALG_KDF1_SP800_56A.value) {
            return TPM_ALG_KDF1_SP800_56A;
        } else if (value == TPM_ALG_KDF2.value) {
            return TPM_ALG_KDF2;
        } else if (value == TPM_ALG_KDF1_SP800_108.value) {
            return TPM_ALG_KDF1_SP800_108;
        } else if (value == TPM_ALG_ECC.value) {
            return TPM_ALG_ECC;
        } else if (value == TPM_ALG_SYMCIPHER.value) {
            return TPM_ALG_SYMCIPHER;
        } else if (value == TPM_ALG_CAMELLIA.value) {
            return TPM_ALG_CAMELLIA;
        } else if (value == TPM_ALG_CTR.value) {
            return TPM_ALG_CTR;
        } else if (value == TPM_ALG_OFB.value) {
            return TPM_ALG_OFB;
        } else if (value == TPM_ALG_CBC.value) {
            return TPM_ALG_CBC;
        } else if (value == TPM_ALG_CFB.value) {
            return TPM_ALG_CFB;
        } else if (value == TPM_ALG_ECB.value) {
            return TPM_ALG_ECB;
        } else {
            throw new InvalidFormatException(null, "value is out of range", value, TPMIAlgPublic.class);
        }
    }

    @JsonValue
    public int getValue() {
        return value;
    }

}
