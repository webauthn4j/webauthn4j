package com.webauthn4j.data;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.jackson.deserializer.json.PublicKeyRepresentationFormatFromStringDeserializer;
import com.webauthn4j.converter.jackson.serializer.json.PublicKeyRepresentationFormatToStringSerializer;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

class PublicKeyRepresentationFormatTest {

    private final ObjectConverter objectConverter = new ObjectConverter();
    private final JsonConverter jsonConverter = objectConverter.getJsonConverter();

    @Test
    void create_test() {
        assertAll(
                () -> assertThat(PublicKeyRepresentationFormat.create(0x0100)).isEqualTo(PublicKeyRepresentationFormat.ECC_X962_RAW),
                () -> assertThat(PublicKeyRepresentationFormat.create(0x0101)).isEqualTo(PublicKeyRepresentationFormat.ECC_X962_DER),
                () -> assertThat(PublicKeyRepresentationFormat.create(0x0102)).isEqualTo(PublicKeyRepresentationFormat.RSA_2048_RAW),
                () -> assertThat(PublicKeyRepresentationFormat.create(0x0103)).isEqualTo(PublicKeyRepresentationFormat.RSA_2048_DER),
                () -> assertThat(PublicKeyRepresentationFormat.create(0x0104)).isEqualTo(PublicKeyRepresentationFormat.COSE),
                () -> assertThat(PublicKeyRepresentationFormat.create("ecc_x962_raw")).isEqualTo(PublicKeyRepresentationFormat.ECC_X962_RAW),
                () -> assertThat(PublicKeyRepresentationFormat.create("ecc_x962_der")).isEqualTo(PublicKeyRepresentationFormat.ECC_X962_DER),
                () -> assertThat(PublicKeyRepresentationFormat.create("rsa_2048_raw")).isEqualTo(PublicKeyRepresentationFormat.RSA_2048_RAW),
                () -> assertThat(PublicKeyRepresentationFormat.create("rsa_2048_der")).isEqualTo(PublicKeyRepresentationFormat.RSA_2048_DER),
                () -> assertThat(PublicKeyRepresentationFormat.create("cose")).isEqualTo(PublicKeyRepresentationFormat.COSE)
        );
    }

    @Test
    void getValue_test() {
        assertThat(PublicKeyRepresentationFormat.ECC_X962_RAW.getValue()).isEqualTo(0x0100);
    }

    @Test
    void toString_test() {
        assertThat(PublicKeyRepresentationFormat.ECC_X962_RAW).hasToString("ecc_x962_raw");
    }

    @Nested
    class IntSerialization {

        @Test
        void serialize_test(){
            PublicKeyRepresentationFormatTest.IntSerializationTestDTO dto = new PublicKeyRepresentationFormatTest.IntSerializationTestDTO();
            dto.publicKeyRepresentationFormat = PublicKeyRepresentationFormat.ECC_X962_RAW;
            String string = jsonConverter.writeValueAsString(dto);
            assertThat(string).isEqualTo("{\"publicKeyRepresentationFormat\":256}");
        }

        @Test
        void deserialize_test() {
            PublicKeyRepresentationFormatTest.IntSerializationTestDTO dto = jsonConverter.readValue("{\"publicKeyRepresentationFormat\":256}", PublicKeyRepresentationFormatTest.IntSerializationTestDTO.class);
            assertThat(dto.publicKeyRepresentationFormat).isEqualTo(PublicKeyRepresentationFormat.ECC_X962_RAW);
        }

        @Test
        void deserialize_test_with_out_of_range_value() {
            assertThatThrownBy(
                    () -> jsonConverter.readValue("{\"publicKeyRepresentationFormat\": \"-1\"}", PublicKeyRepresentationFormatTest.IntSerializationTestDTO.class)
            ).isInstanceOf(DataConversionException.class);
        }

        @Test
        void deserialize_test_with_invalid_value() {
            assertThatThrownBy(
                    () -> jsonConverter.readValue("{\"publicKeyRepresentationFormat\": \"\"}", PublicKeyRepresentationFormatTest.IntSerializationTestDTO.class)
            ).isInstanceOf(DataConversionException.class);
        }

        @Test
        void deserialize_test_with_null() {
            PublicKeyRepresentationFormatTest.IntSerializationTestDTO data = jsonConverter.readValue("{\"publicKeyRepresentationFormat\":null}", PublicKeyRepresentationFormatTest.IntSerializationTestDTO.class);
            assertThat(data.publicKeyRepresentationFormat).isNull();
        }
    }

    static class IntSerializationTestDTO {
        @SuppressWarnings("WeakerAccess")
        public PublicKeyRepresentationFormat publicKeyRepresentationFormat;
    }

    @Nested
    class StringSerialization {

        @Test
        void serialize_test(){
            PublicKeyRepresentationFormatTest.StringSerializationTestDTO dto = new PublicKeyRepresentationFormatTest.StringSerializationTestDTO();
            dto.publicKeyRepresentationFormat = PublicKeyRepresentationFormat.ECC_X962_RAW;
            String string = jsonConverter.writeValueAsString(dto);
            assertThat(string).isEqualTo("{\"publicKeyRepresentationFormat\":\"ecc_x962_raw\"}");
        }

        @Test
        void deserialize_test() {
            PublicKeyRepresentationFormatTest.StringSerializationTestDTO dto = jsonConverter.readValue("{\"publicKeyRepresentationFormat\":\"ecc_x962_raw\"}", PublicKeyRepresentationFormatTest.StringSerializationTestDTO.class);
            assertThat(dto.publicKeyRepresentationFormat).isEqualTo(PublicKeyRepresentationFormat.ECC_X962_RAW);
        }

        @Test
        void deserialize_test_with_invalid_value() {
            assertThatThrownBy(
                    () -> jsonConverter.readValue("{\"publicKeyRepresentationFormat\": \"\"}", PublicKeyRepresentationFormatTest.StringSerializationTestDTO.class)
            ).isInstanceOf(DataConversionException.class);
        }

        @Test
        void deserialize_test_with_null() {
            PublicKeyRepresentationFormatTest.StringSerializationTestDTO data = jsonConverter.readValue("{\"publicKeyRepresentationFormat\":null}", PublicKeyRepresentationFormatTest.StringSerializationTestDTO.class);
            assertThat(data.publicKeyRepresentationFormat).isNull();
        }
    }

    static class StringSerializationTestDTO {
        @SuppressWarnings("WeakerAccess")
        @JsonSerialize(using = PublicKeyRepresentationFormatToStringSerializer.class)
        @JsonDeserialize(using = PublicKeyRepresentationFormatFromStringDeserializer.class)
        public PublicKeyRepresentationFormat publicKeyRepresentationFormat;
    }

}