package com.webauthn4j.data;

import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.jackson.deserializer.json.AuthenticationAlgorithmFromStringDeserializer;
import com.webauthn4j.converter.jackson.serializer.json.AuthenticationAlgorithmToStringSerializer;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import tools.jackson.core.exc.StreamReadException;
import tools.jackson.databind.annotation.JsonDeserialize;
import tools.jackson.databind.annotation.JsonSerialize;
import tools.jackson.databind.exc.InvalidFormatException;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

class AuthenticationAlgorithmTest {

    private final ObjectConverter objectConverter = new ObjectConverter();
    private final JsonMapper jsonMapper = objectConverter.getJsonMapper();


    @Nested
    class BasicOperations {

        @Test
        void shouldReturnCorrectValue() {
            assertAll(
                    "All AuthenticationAlgorithm values should return their correct respective values",
                    () -> assertThat(AuthenticationAlgorithm.SECP256R1_ECDSA_SHA256_RAW.getValue()).isEqualTo(0x0001),
                    () -> assertThat(AuthenticationAlgorithm.SECP256R1_ECDSA_SHA256_DER.getValue()).isEqualTo(0x0002),
                    () -> assertThat(AuthenticationAlgorithm.RSASSA_PSS_SHA256_RAW.getValue()).isEqualTo(0x0003),
                    () -> assertThat(AuthenticationAlgorithm.RSA_EMSA_PKCS1_SHA256_RAW.getValue()).isEqualTo(0x0008),
                    () -> assertThat(AuthenticationAlgorithm.ED25519_EDDSA_SHA512_RAW.getValue()).isEqualTo(0x0012)
            );
        }

        @Test
        void shouldConvertToStringCorrectly() {
            assertAll(
                    "All AuthenticationAlgorithm values should convert to string correctly",
                    () -> assertThat(AuthenticationAlgorithm.SECP256R1_ECDSA_SHA256_RAW).hasToString("secp256r1_ecdsa_sha256_raw"),
                    () -> assertThat(AuthenticationAlgorithm.SECP256R1_ECDSA_SHA256_DER).hasToString("secp256r1_ecdsa_sha256_der"),
                    () -> assertThat(AuthenticationAlgorithm.RSASSA_PSS_SHA256_RAW).hasToString("rsassa_pss_sha256_raw"),
                    () -> assertThat(AuthenticationAlgorithm.RSASSA_PSS_SHA256_DER).hasToString("rsassa_pss_sha256_der"),
                    () -> assertThat(AuthenticationAlgorithm.ED25519_EDDSA_SHA512_RAW).hasToString("ed25519_eddsa_sha512_raw")
            );
        }
    }

    @Nested
    class CreateMethod {

        @SuppressWarnings("java:S5961")
        @Test
        void shouldCreateFromValidIntValues() {
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
                    () -> assertThat(AuthenticationAlgorithm.create(0x0012)).isEqualTo(AuthenticationAlgorithm.ED25519_EDDSA_SHA512_RAW)
            );
        }

        @SuppressWarnings("java:S5961")
        @Test
        void shouldCreateFromValidStringValues() {
            assertAll(
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
                    () -> assertThat(AuthenticationAlgorithm.create("secp521r1_ecdsa_sha512_raw")).isEqualTo(AuthenticationAlgorithm.SECP521R1_ECDSA_SHA512_RAW),
                    () -> assertThat(AuthenticationAlgorithm.create("ed25519_eddsa_sha512_raw")).isEqualTo(AuthenticationAlgorithm.ED25519_EDDSA_SHA512_RAW)
            );
        }
        
        @Test
        void shouldThrowExceptionForInvalidIntValue() {
            assertThatThrownBy(() -> AuthenticationAlgorithm.create(-1))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("value");

            assertThatThrownBy(() -> AuthenticationAlgorithm.create(0x0013)) // undefined value
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("value");
                    
            assertThatThrownBy(() -> AuthenticationAlgorithm.create(65536)) // exceeds unsigned short max
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("value");
        }
        
        @Test
        void shouldThrowExceptionForInvalidStringValue() {
            assertThatThrownBy(() -> AuthenticationAlgorithm.create("invalid_algorithm"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("value");
                    
            assertThatThrownBy(() -> AuthenticationAlgorithm.create(""))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("value");
                    
            assertThatThrownBy(() -> AuthenticationAlgorithm.create((String) null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("value");
        }
    }

    @Nested
    class IntSerialization {

        @Test
        void shouldSerializeToJson() {
            IntSerializationTestDTO dto = new IntSerializationTestDTO();
            dto.authenticationAlgorithm = AuthenticationAlgorithm.SECP256R1_ECDSA_SHA256_RAW;
            String string = jsonMapper.writeValueAsString(dto);
            assertThat(string).isEqualTo("{\"authenticationAlgorithm\":1}");
        }

        @Test
        void shouldDeserializeFromJson() {
            IntSerializationTestDTO dto = jsonMapper.readValue("{\"authenticationAlgorithm\":1}", IntSerializationTestDTO.class);
            assertThat(dto.authenticationAlgorithm).isEqualTo(AuthenticationAlgorithm.SECP256R1_ECDSA_SHA256_RAW);
        }

        @Test
        void shouldThrowExceptionWhenDeserializingOutOfRangeValue() {
            assertThatThrownBy(
                    () -> jsonMapper.readValue("{\"authenticationAlgorithm\": \"-1\"}", IntSerializationTestDTO.class)
            ).isInstanceOf(InvalidFormatException.class);
        }

        @Test
        void shouldThrowExceptionWhenDeserializingInvalidValue() {
            assertThatThrownBy(
                    () -> jsonMapper.readValue("{\"authenticationAlgorithm\": \"\"}", IntSerializationTestDTO.class)
            ).isInstanceOf(InvalidFormatException.class);
        }

        @Test
        void shouldDeserializeNullToNull() {
            IntSerializationTestDTO data = jsonMapper.readValue("{\"authenticationAlgorithm\":null}", IntSerializationTestDTO.class);
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
        void shouldSerializeToJsonString() {
            StringSerializationTestDTO dto = new StringSerializationTestDTO();
            dto.authenticationAlgorithm = AuthenticationAlgorithm.SECP256R1_ECDSA_SHA256_RAW;
            String string = jsonMapper.writeValueAsString(dto);
            assertThat(string).isEqualTo("{\"authenticationAlgorithm\":\"secp256r1_ecdsa_sha256_raw\"}");
        }

        @Test
        void shouldDeserializeFromJsonString() {
            StringSerializationTestDTO dto = jsonMapper.readValue("{\"authenticationAlgorithm\": \"secp256r1_ecdsa_sha256_raw\"}", StringSerializationTestDTO.class);
            assertThat(dto.authenticationAlgorithm).isEqualTo(AuthenticationAlgorithm.SECP256R1_ECDSA_SHA256_RAW);
        }

        @Test
        void shouldThrowExceptionWhenDeserializingInvalidString() {
            assertThatThrownBy(
                    () -> jsonMapper.readValue("{\"authenticationAlgorithm\": \"invalid\"}", StringSerializationTestDTO.class)
            ).isInstanceOf(InvalidFormatException.class);
        }

        @Test
        void shouldDeserializeNullToNull() {
            StringSerializationTestDTO data = jsonMapper.readValue("{\"authenticationAlgorithm\":null}", StringSerializationTestDTO.class);
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