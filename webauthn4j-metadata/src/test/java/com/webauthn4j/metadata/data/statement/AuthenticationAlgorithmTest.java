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

import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.util.UnsignedNumberUtil;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Java6Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("ResultOfMethodCallIgnored")
class AuthenticationAlgorithmTest {

    private JsonConverter jsonConverter = new JsonConverter();

    @Test
    void create_test() {
        assertAll(
                () -> assertThat(AuthenticationAlgorithm.create(0x0001)).isEqualTo(AuthenticationAlgorithm.SECP256R1_ECDSA_SHA256_RAW),
                () -> assertThat(AuthenticationAlgorithm.create(0x0002)).isEqualTo(AuthenticationAlgorithm.SECP256R1_ECDSA_SHA256_DER),
                () -> assertThat(AuthenticationAlgorithm.create(0x0003)).isEqualTo(AuthenticationAlgorithm.RSASSA_PSS_SHA256_RAW),
                () -> assertThat(AuthenticationAlgorithm.create(0x0004)).isEqualTo(AuthenticationAlgorithm.RSASSA_PSS_SHA256_DER),
                () -> assertThat(AuthenticationAlgorithm.create(0x0005)).isEqualTo(AuthenticationAlgorithm.SECP256K1_ECDSA_SHA256_RAW),
                () -> assertThat(AuthenticationAlgorithm.create(0x0006)).isEqualTo(AuthenticationAlgorithm.SECP256K1_ECDSA_SHA256_DER),
                () -> assertThat(AuthenticationAlgorithm.create(0x0007)).isEqualTo(AuthenticationAlgorithm.SM2_SM3_RAW),
                () -> assertThat(AuthenticationAlgorithm.create(0x0008)).isEqualTo(AuthenticationAlgorithm.RSA_EMSA_PKCS1_SHA256_RAW),
                () -> assertThat(AuthenticationAlgorithm.create(0x0009)).isEqualTo(AuthenticationAlgorithm.RSA_EMSA_PKCS1_SHA256_DER),
                () -> assertThat(AuthenticationAlgorithm.create(0x000A)).isEqualTo(AuthenticationAlgorithm.RSASSA_PSS_SHA384_RAW),
                () -> assertThat(AuthenticationAlgorithm.create(0x000B)).isEqualTo(AuthenticationAlgorithm.RSASSA_PSS_SHA512_RAW),
                () -> assertThat(AuthenticationAlgorithm.create(0x000C)).isEqualTo(AuthenticationAlgorithm.RSASSA_PKCSV15_SHA256_RAW),
                () -> assertThat(AuthenticationAlgorithm.create(0x000D)).isEqualTo(AuthenticationAlgorithm.RSASSA_PKCSV15_SHA384_RAW),
                () -> assertThat(AuthenticationAlgorithm.create(0x000E)).isEqualTo(AuthenticationAlgorithm.RSASSA_PKCSV15_SHA512_RAW),
                () -> assertThat(AuthenticationAlgorithm.create(0x000F)).isEqualTo(AuthenticationAlgorithm.RSASSA_PKCSV15_SHA1_RAW),
                () -> assertThat(AuthenticationAlgorithm.create(0x0010)).isEqualTo(AuthenticationAlgorithm.SECP384R1_ECDSA_SHA384_RAW),
                () -> assertThat(AuthenticationAlgorithm.create(0x0011)).isEqualTo(AuthenticationAlgorithm.SECP521R1_ECDSA_SHA512_RAW),
                () -> assertThat(AuthenticationAlgorithm.create(0x0012)).isEqualTo(AuthenticationAlgorithm.ED25519_EDDSA_SHA256_RAW),
                () -> assertThrows(IllegalArgumentException.class,
                        () -> AuthenticationAlgorithm.create(UnsignedNumberUtil.UNSIGNED_SHORT_MAX + 1)),
                () -> assertThrows(IllegalArgumentException.class,
                        () -> AuthenticationAlgorithm.create(-1)),
                () -> assertThrows(IllegalArgumentException.class,
                        () -> AuthenticationAlgorithm.create(0x0000))
        );
    }

    @Test
    void getValue_test() {
        assertThat(AuthenticationAlgorithm.SECP256R1_ECDSA_SHA256_DER.getValue()).isEqualTo(0x0002);
    }

    @Test
    void fromInt_test() {
        TestDTO dto = jsonConverter.readValue("{\"authentication_algorithm\":6}", TestDTO.class);

        assertAll(
                () -> assertThat(dto.authentication_algorithm).isEqualTo(AuthenticationAlgorithm.SECP256K1_ECDSA_SHA256_DER),
                () -> assertThrows(DataConversionException.class,
                        () -> jsonConverter.readValue("{\"authentication_algorithm\":65536}", TestDTO.class))
        );
    }

    static class TestDTO {
        @SuppressWarnings("WeakerAccess")
        public AuthenticationAlgorithm authentication_algorithm;
    }
}
