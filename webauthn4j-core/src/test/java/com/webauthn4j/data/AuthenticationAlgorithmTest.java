package com.webauthn4j.data;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.jackson.deserializer.json.AuthenticationAlgorithmFromStringDeserializer;
import com.webauthn4j.converter.jackson.serializer.json.AuthenticationAlgorithmToStringSerializer;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

class AuthenticationAlgorithmTest {

    private final ObjectConverter objectConverter = new ObjectConverter();
    private final JsonConverter jsonConverter = objectConverter.getJsonConverter();

    @SuppressWarnings("java:S5961")
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
                () -> assertThat(AuthenticationAlgorithm.create(0x0011)).isEqualTo(AuthenticationAlgorithm.SECP521R1_ECDSA_SHA256_RAW),
                () -> assertThat(AuthenticationAlgorithm.create(0x0012)).isEqualTo(AuthenticationAlgorithm.ED25519_EDDSA_SHA512_RAW),
                () -> assertThat(AuthenticationAlgorithm.create("secp256r1_ecdsa_sha256_raw")).isEqualTo(AuthenticationAlgorithm.SECP256R1_ECDSA_SHA256_RAW),
                () -> assertThat(AuthenticationAlgorithm.create("secp256r1_ecdsa_sha256_der")).isEqualTo(AuthenticationAlgorithm.SECP256R1_ECDSA_SHA256_DER),
                () -> assertThat(AuthenticationAlgorithm.create("rsassa_pss_sha256_raw")).isEqualTo(AuthenticationAlgorithm.RSASSA_PSS_SHA256_RAW),
                () -> assertThat(AuthenticationAlgorithm.create("rsassa_pss_sha256_der")).isEqualTo(AuthenticationAlgorithm.RSASSA_PSS_SHA256_DER),
                () -> assertThat(AuthenticationAlgorithm.create("secp256k1_ecdsa_sha256_raw")).isEqualTo(AuthenticationAlgorithm.SECP256K1_ECDSA_SHA256_RAW),
                () -> assertThat(AuthenticationAlgorithm.create("secp256k1_ecdsa_sha256_der")).isEqualTo(AuthenticationAlgorithm.SECP256K1_ECDSA_SHA256_DER),
                () -> assertThat(AuthenticationAlgorithm.create("sm2_sm3_raw")).isEqualTo(AuthenticationAlgorithm.SM2_SM3_RAW),
                () -> assertThat(AuthenticationAlgorithm.create("rsa_emsa_pkcs1_sha256_raw")).isEqualTo(AuthenticationAlgorithm.RSA_EMSA_PKCS1_SHA256_RAW),
                () -> assertThat(AuthenticationAlgorithm.create("rsa_emsa_pkcs1_sha256_der")).isEqualTo(AuthenticationAlgorithm.RSA_EMSA_PKCS1_SHA256_DER),
                () -> assertThat(AuthenticationAlgorithm.create("rsassa_pss_sha384_raw")).isEqualTo(AuthenticationAlgorithm.RSASSA_PSS_SHA384_RAW),
                () -> assertThat(AuthenticationAlgorithm.create("rsassa_pss_sha512_raw")).isEqualTo(AuthenticationAlgorithm.RSASSA_PSS_SHA512_RAW),
                () -> assertThat(AuthenticationAlgorithm.create("rsassa_pkcsv15_sha256_raw")).isEqualTo(AuthenticationAlgorithm.RSASSA_PKCSV15_SHA256_RAW),
                () -> assertThat(AuthenticationAlgorithm.create("rsassa_pkcsv15_sha384_raw")).isEqualTo(AuthenticationAlgorithm.RSASSA_PKCSV15_SHA384_RAW),
                () -> assertThat(AuthenticationAlgorithm.create("rsassa_pkcsv15_sha512_raw")).isEqualTo(AuthenticationAlgorithm.RSASSA_PKCSV15_SHA512_RAW),
                () -> assertThat(AuthenticationAlgorithm.create("rsassa_pkcsv15_sha1_raw")).isEqualTo(AuthenticationAlgorithm.RSASSA_PKCSV15_SHA1_RAW),
                () -> assertThat(AuthenticationAlgorithm.create("secp384r1_ecdsa_sha384_raw")).isEqualTo(AuthenticationAlgorithm.SECP384R1_ECDSA_SHA384_RAW),
                () -> assertThat(AuthenticationAlgorithm.create("secp521r1_ecdsa_sha256_raw")).isEqualTo(AuthenticationAlgorithm.SECP521R1_ECDSA_SHA256_RAW),
                () -> assertThat(AuthenticationAlgorithm.create("ed25519_eddsa_sha512_raw")).isEqualTo(AuthenticationAlgorithm.ED25519_EDDSA_SHA512_RAW)
        );
    }


    @Test
    void getValue_test() {
        assertThat(AuthenticationAlgorithm.SECP256R1_ECDSA_SHA256_RAW.getValue()).isEqualTo(0x0001);
    }

    @Test
    void toString_test() {
        assertThat(AuthenticationAlgorithm.SECP256R1_ECDSA_SHA256_RAW).hasToString("secp256r1_ecdsa_sha256_raw");
    }

    @Nested
    class IntSerialization {

        @Test
        void serialize_test(){
            IntSerializationTestDTO dto = new IntSerializationTestDTO();
            dto.authenticationAlgorithm = AuthenticationAlgorithm.SECP256R1_ECDSA_SHA256_RAW;
            String string = jsonConverter.writeValueAsString(dto);
            assertThat(string).isEqualTo("{\"authenticationAlgorithm\":1}");
        }

        @Test
        void deserialize_test() {
            IntSerializationTestDTO dto = jsonConverter.readValue("{\"authenticationAlgorithm\":1}", IntSerializationTestDTO.class);
            assertThat(dto.authenticationAlgorithm).isEqualTo(AuthenticationAlgorithm.SECP256R1_ECDSA_SHA256_RAW);
        }

        @Test
        void deserialize_test_with_out_of_range_value() {
            assertThatThrownBy(
                    () -> jsonConverter.readValue("{\"authenticationAlgorithm\": \"-1\"}", IntSerializationTestDTO.class)
            ).isInstanceOf(DataConversionException.class);
        }

        @Test
        void deserialize_test_with_invalid_value() {
            assertThatThrownBy(
                    () -> jsonConverter.readValue("{\"authenticationAlgorithm\": \"\"}", AuthenticationAlgorithmTest.IntSerializationTestDTO.class)
            ).isInstanceOf(DataConversionException.class);
        }

        @Test
        void deserialize_test_with_null() {
            AuthenticationAlgorithmTest.IntSerializationTestDTO data = jsonConverter.readValue("{\"authenticationAlgorithm\":null}", AuthenticationAlgorithmTest.IntSerializationTestDTO.class);
            assertThat(data.authenticationAlgorithm).isNull();
        }

    }

    static class IntSerializationTestDTO {
        @SuppressWarnings("WeakerAccess")
        public AuthenticationAlgorithm authenticationAlgorithm;
    }

    @Nested
    class StringSerialization {

        @Test
        void serialize_test(){
            StringSerializationTestDTO dto = new StringSerializationTestDTO();
            dto.authenticationAlgorithm = AuthenticationAlgorithm.SECP256R1_ECDSA_SHA256_RAW;
            String string = jsonConverter.writeValueAsString(dto);
            assertThat(string).isEqualTo("{\"authenticationAlgorithm\":\"secp256r1_ecdsa_sha256_raw\"}");
        }

        @Test
        void deserialize_test() {
            StringSerializationTestDTO dto = jsonConverter.readValue("{\"authenticationAlgorithm\": \"secp256r1_ecdsa_sha256_raw\"}", StringSerializationTestDTO.class);
            assertThat(dto.authenticationAlgorithm).isEqualTo(AuthenticationAlgorithm.SECP256R1_ECDSA_SHA256_RAW);
        }

        @Test
        void deserialize_test_with_invalid_value() {
            assertThatThrownBy(
                    () -> jsonConverter.readValue("{\"authenticationAlgorithm\": \"invalid\"}", StringSerializationTestDTO.class)
            ).isInstanceOf(DataConversionException.class);
        }

        @Test
        void deserialize_test_with_null() {
            StringSerializationTestDTO data = jsonConverter.readValue("{\"authenticationAlgorithm\":null}", StringSerializationTestDTO.class);
            assertThat(data.authenticationAlgorithm).isNull();
        }

    }

    static class StringSerializationTestDTO {
        @JsonSerialize(using = AuthenticationAlgorithmToStringSerializer.class)
        @JsonDeserialize(using = AuthenticationAlgorithmFromStringDeserializer.class)
        @SuppressWarnings("WeakerAccess")
        public AuthenticationAlgorithm authenticationAlgorithm;
    }

}