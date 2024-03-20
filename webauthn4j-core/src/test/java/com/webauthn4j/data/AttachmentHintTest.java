package com.webauthn4j.data;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.jackson.deserializer.json.AttachmentHintFromStringDeserializer;
import com.webauthn4j.converter.jackson.serializer.json.AttachmentHintToStringSerializer;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

class AttachmentHintTest {


    private final ObjectConverter objectConverter = new ObjectConverter();
    private final JsonConverter jsonConverter = objectConverter.getJsonConverter();

    @Test
    void create_test() {
        assertAll(
                () -> assertThat(AttachmentHint.create(0x0001)).isEqualTo(AttachmentHint.INTERNAL),
                () -> assertThat(AttachmentHint.create(0x0002)).isEqualTo(AttachmentHint.EXTERNAL),
                () -> assertThat(AttachmentHint.create(0x0004)).isEqualTo(AttachmentHint.WIRED),
                () -> assertThat(AttachmentHint.create(0x0008)).isEqualTo(AttachmentHint.WIRELESS),
                () -> assertThat(AttachmentHint.create(0x0010)).isEqualTo(AttachmentHint.NFC),
                () -> assertThat(AttachmentHint.create(0x0020)).isEqualTo(AttachmentHint.BLUETOOTH),
                () -> assertThat(AttachmentHint.create(0x0040)).isEqualTo(AttachmentHint.NETWORK),
                () -> assertThat(AttachmentHint.create(0x0080)).isEqualTo(AttachmentHint.READY),
                () -> assertThat(AttachmentHint.create(0x0100)).isEqualTo(AttachmentHint.WIFI_DIRECT),
                () -> assertThat(AttachmentHint.create("internal")).isEqualTo(AttachmentHint.INTERNAL),
                () -> assertThat(AttachmentHint.create("external")).isEqualTo(AttachmentHint.EXTERNAL),
                () -> assertThat(AttachmentHint.create("wired")).isEqualTo(AttachmentHint.WIRED),
                () -> assertThat(AttachmentHint.create("wireless")).isEqualTo(AttachmentHint.WIRELESS),
                () -> assertThat(AttachmentHint.create("nfc")).isEqualTo(AttachmentHint.NFC),
                () -> assertThat(AttachmentHint.create("bluetooth")).isEqualTo(AttachmentHint.BLUETOOTH),
                () -> assertThat(AttachmentHint.create("network")).isEqualTo(AttachmentHint.NETWORK),
                () -> assertThat(AttachmentHint.create("ready")).isEqualTo(AttachmentHint.READY),
                () -> assertThat(AttachmentHint.create("wifi_direct")).isEqualTo(AttachmentHint.WIFI_DIRECT)
        );
    }

    @Test
    void getValue_test() {
        assertThat(AttachmentHint.INTERNAL.getValue()).isEqualTo(0x0001);
    }

    @Test
    void toString_test() {
        assertThat(AttachmentHint.INTERNAL).hasToString("internal");
    }

    @Nested
    class IntSerialization {

        @Test
        void serialize_test(){
            IntSerializationTestDTO dto = new IntSerializationTestDTO();
            dto.attachmentHint = AttachmentHint.EXTERNAL;
            String string = jsonConverter.writeValueAsString(dto);
            assertThat(string).isEqualTo("{\"attachmentHint\":2}");
        }

        @Test
        void deserialize_test() {
            IntSerializationTestDTO dto = jsonConverter.readValue("{\"attachmentHint\":2}", IntSerializationTestDTO.class);
            assertThat(dto.attachmentHint).isEqualTo(AttachmentHint.EXTERNAL);
        }

        @Test
        void deserialize_test_with_out_of_range_value() {
            assertThatThrownBy(
                    () -> jsonConverter.readValue("{\"attachmentHint\": \"-1\"}", IntSerializationTestDTO.class)
            ).isInstanceOf(DataConversionException.class);
        }

        @Test
        void deserialize_test_with_invalid_value() {
            assertThatThrownBy(
                    () -> jsonConverter.readValue("{\"attachmentHint\": \"\"}", IntSerializationTestDTO.class)
            ).isInstanceOf(DataConversionException.class);
        }

        @Test
        void deserialize_test_with_null() {
            IntSerializationTestDTO data = jsonConverter.readValue("{\"attachmentHint\":null}", IntSerializationTestDTO.class);
            assertThat(data.attachmentHint).isNull();
        }

    }

    static class IntSerializationTestDTO {
        @SuppressWarnings("WeakerAccess")
        public AttachmentHint attachmentHint;
    }

    @Nested
    class StringSerialization {

        @Test
        void serialize_test(){
            StringSerializationTestDTO dto = new StringSerializationTestDTO();
            dto.attachmentHint = AttachmentHint.INTERNAL;
            String string = jsonConverter.writeValueAsString(dto);
            assertThat(string).isEqualTo("{\"attachmentHint\":\"internal\"}");
        }

        @Test
        void deserialize_test() {
            StringSerializationTestDTO dto = jsonConverter.readValue("{\"attachmentHint\":\"internal\"}", StringSerializationTestDTO.class);
            assertThat(dto.attachmentHint).isEqualTo(AttachmentHint.INTERNAL);
        }

        @Test
        void deserialize_test_with_invalid_value() {
            assertThatThrownBy(
                    () -> jsonConverter.readValue("{\"attachmentHint\": \"invalid\"}", StringSerializationTestDTO.class)
            ).isInstanceOf(DataConversionException.class);
        }

        @Test
        void deserialize_test_with_null() {
            StringSerializationTestDTO data = jsonConverter.readValue("{\"attachmentHint\":null}", StringSerializationTestDTO.class);
            assertThat(data.attachmentHint).isNull();
        }

    }

    static class StringSerializationTestDTO {
        @JsonSerialize(using = AttachmentHintToStringSerializer.class)
        @JsonDeserialize(using = AttachmentHintFromStringDeserializer.class)
        @SuppressWarnings("WeakerAccess")
        public AttachmentHint attachmentHint;
    }
}