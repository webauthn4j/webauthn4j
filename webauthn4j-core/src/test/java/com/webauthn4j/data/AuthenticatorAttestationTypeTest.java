package com.webauthn4j.data;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.jackson.deserializer.json.AttachmentHintFromStringDeserializer;
import com.webauthn4j.converter.jackson.deserializer.json.AuthenticatorAttestationTypeFromStringDeserializer;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.*;

class AuthenticatorAttestationTypeTest {

    private final ObjectConverter objectConverter = new ObjectConverter();
    private final JsonConverter jsonConverter = objectConverter.getJsonConverter();

    @Test
    void create_test() {
        assertAll(
                () -> assertThat(AuthenticatorAttestationType.create(0x3E07)).isEqualTo(AuthenticatorAttestationType.BASIC_FULL),
                () -> assertThat(AuthenticatorAttestationType.create(0x3E08)).isEqualTo(AuthenticatorAttestationType.BASIC_SURROGATE),
                () -> assertThat(AuthenticatorAttestationType.create(0x3E09)).isEqualTo(AuthenticatorAttestationType.ECDAA),
                () -> assertThat(AuthenticatorAttestationType.create(0x3E0A)).isEqualTo(AuthenticatorAttestationType.ATTCA),
                () -> assertThat(AuthenticatorAttestationType.create("basic_full")).isEqualTo(AuthenticatorAttestationType.BASIC_FULL),
                () -> assertThat(AuthenticatorAttestationType.create("basic_surrogate")).isEqualTo(AuthenticatorAttestationType.BASIC_SURROGATE),
                () -> assertThat(AuthenticatorAttestationType.create("ecdaa")).isEqualTo(AuthenticatorAttestationType.ECDAA),
                () -> assertThat(AuthenticatorAttestationType.create("attca")).isEqualTo(AuthenticatorAttestationType.ATTCA)
        );
    }

    @Test
    void getValue_test() {
        assertThat(AuthenticatorAttestationType.BASIC_FULL.getValue()).isEqualTo(0x3E07);
    }

    @Test
    void toString_test() {
        assertThat(AuthenticatorAttestationType.BASIC_FULL).hasToString("basic_full");
    }

    @Nested
    class IntSerialization {

        @Test
        void deserialize_test() {
            AuthenticatorAttestationTypeTest.IntSerializationTestDTO dto = jsonConverter.readValue("{\"authenticatorAttestationType\": 15879}", AuthenticatorAttestationTypeTest.IntSerializationTestDTO.class);
            assertThat(dto.authenticatorAttestationType).isEqualTo(AuthenticatorAttestationType.BASIC_FULL);
        }

        @Test
        void deserialize_test_with_out_of_range_value() {
            assertThatThrownBy(
                    () -> jsonConverter.readValue("{\"authenticatorAttestationType\": \"-1\"}", AuthenticatorAttestationTypeTest.IntSerializationTestDTO.class)
            ).isInstanceOf(DataConversionException.class);
        }

        @Test
        void deserialize_test_with_invalid_value() {
            assertThatThrownBy(
                    () -> jsonConverter.readValue("{\"authenticatorAttestationType\": \"\"}", AuthenticatorAttestationTypeTest.IntSerializationTestDTO.class)
            ).isInstanceOf(DataConversionException.class);
        }

        @Test
        void deserialize_test_with_null() {
            AuthenticatorAttestationTypeTest.IntSerializationTestDTO data = jsonConverter.readValue("{\"authenticatorAttestationType\":null}", AuthenticatorAttestationTypeTest.IntSerializationTestDTO.class);
            assertThat(data.authenticatorAttestationType).isNull();
        }

    }

    static class IntSerializationTestDTO {
        @SuppressWarnings("WeakerAccess")
        public AuthenticatorAttestationType authenticatorAttestationType;
    }

    @Nested
    class StringSerialization {

        @Test
        void deserialize_test() {
            AuthenticatorAttestationTypeTest.StringSerializationTestDTO dto = jsonConverter.readValue("{\"authenticatorAttestationType\": \"basic_full\"}", AuthenticatorAttestationTypeTest.StringSerializationTestDTO.class);
            assertThat(dto.authenticatorAttestationType).isEqualTo(AuthenticatorAttestationType.BASIC_FULL);
        }

        @Test
        void deserialize_test_with_invalid_value() {
            assertThatThrownBy(
                    () -> jsonConverter.readValue("{\"authenticatorAttestationType\": \"invalid\"}", AuthenticatorAttestationTypeTest.StringSerializationTestDTO.class)
            ).isInstanceOf(DataConversionException.class);
        }

        @Test
        void deserialize_test_with_null() {
            AuthenticatorAttestationTypeTest.StringSerializationTestDTO data = jsonConverter.readValue("{\"authenticatorAttestationType\":null}", AuthenticatorAttestationTypeTest.StringSerializationTestDTO.class);
            assertThat(data.authenticatorAttestationType).isNull();
        }

    }

    static class StringSerializationTestDTO {
        @JsonDeserialize(using = AuthenticatorAttestationTypeFromStringDeserializer.class)
        @SuppressWarnings("WeakerAccess")
        public AuthenticatorAttestationType authenticatorAttestationType;
    }
}