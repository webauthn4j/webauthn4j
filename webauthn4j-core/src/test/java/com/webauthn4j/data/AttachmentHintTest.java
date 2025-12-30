package com.webauthn4j.data;

import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.jackson.deserializer.json.AttachmentHintFromStringDeserializer;
import com.webauthn4j.converter.jackson.serializer.json.AttachmentHintToStringSerializer;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.annotation.JsonDeserialize;
import tools.jackson.databind.annotation.JsonSerialize;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

class AttachmentHintTest {

    private final ObjectConverter objectConverter = new ObjectConverter();
    private final JsonConverter jsonConverter = objectConverter.getJsonConverter();

    @Nested
    class BasicOperations {

        @Test
        void shouldReturnCorrectValue() {
            assertAll(
                    "All AttachmentHint values should return their correct respective values",
                    () -> assertThat(AttachmentHint.INTERNAL.getValue()).isEqualTo(0x0001),
                    () -> assertThat(AttachmentHint.EXTERNAL.getValue()).isEqualTo(0x0002),
                    () -> assertThat(AttachmentHint.WIRED.getValue()).isEqualTo(0x0004),
                    () -> assertThat(AttachmentHint.WIRELESS.getValue()).isEqualTo(0x0008),
                    () -> assertThat(AttachmentHint.NFC.getValue()).isEqualTo(0x0010),
                    () -> assertThat(AttachmentHint.BLUETOOTH.getValue()).isEqualTo(0x0020),
                    () -> assertThat(AttachmentHint.NETWORK.getValue()).isEqualTo(0x0040),
                    () -> assertThat(AttachmentHint.READY.getValue()).isEqualTo(0x0080),
                    () -> assertThat(AttachmentHint.WIFI_DIRECT.getValue()).isEqualTo(0x0100)
            );
        }

        @Test
        void shouldConvertToStringCorrectly() {
            assertThat(AttachmentHint.INTERNAL).hasToString("internal");
        }
    }

    @Nested
    class CreateMethod {

        @Test
        void shouldCreateAttachmentHintFromValidIntValues() {
            assertAll(
                    () -> assertThat(AttachmentHint.create(0x0001)).isEqualTo(AttachmentHint.INTERNAL),
                    () -> assertThat(AttachmentHint.create(0x0002)).isEqualTo(AttachmentHint.EXTERNAL),
                    () -> assertThat(AttachmentHint.create(0x0004)).isEqualTo(AttachmentHint.WIRED),
                    () -> assertThat(AttachmentHint.create(0x0008)).isEqualTo(AttachmentHint.WIRELESS),
                    () -> assertThat(AttachmentHint.create(0x0010)).isEqualTo(AttachmentHint.NFC),
                    () -> assertThat(AttachmentHint.create(0x0020)).isEqualTo(AttachmentHint.BLUETOOTH),
                    () -> assertThat(AttachmentHint.create(0x0040)).isEqualTo(AttachmentHint.NETWORK),
                    () -> assertThat(AttachmentHint.create(0x0080)).isEqualTo(AttachmentHint.READY),
                    () -> assertThat(AttachmentHint.create(0x0100)).isEqualTo(AttachmentHint.WIFI_DIRECT)
            );
        }

        @Test
        void shouldCreateAttachmentHintFromValidStringValues() {
            assertAll(
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
        void shouldThrowExceptionForInvalidIntValue() {
            assertThatThrownBy(() -> AttachmentHint.create(0x0003)) // not a valid value
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("value");
            
            assertThatThrownBy(() -> AttachmentHint.create(-1)) // negative value
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("value");
            
            assertThatThrownBy(() -> AttachmentHint.create(0x1000)) // undefined value
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("value");
        }
        
        @Test
        void shouldThrowExceptionForInvalidStringValue() {
            assertThatThrownBy(() -> AttachmentHint.create("invalid_hint"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("value");
            
            assertThatThrownBy(() -> AttachmentHint.create(""))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("value");
            
            assertThatThrownBy(() -> AttachmentHint.create((String) null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("value");
        }
    }
    
    @Nested
    class IntSerialization {
    
        @Test
        void shouldSerializeToJson(){
            IntSerializationTestDTO dto = new IntSerializationTestDTO();
            dto.attachmentHint = AttachmentHint.EXTERNAL;
            String string = jsonConverter.writeValueAsString(dto);
            assertThat(string).isEqualTo("{\"attachmentHint\":2}");
        }
    
        @Test
        void shouldDeserializeFromJson() {
            IntSerializationTestDTO dto = jsonConverter.readValue("{\"attachmentHint\":2}", IntSerializationTestDTO.class);
            assertThat(dto.attachmentHint).isEqualTo(AttachmentHint.EXTERNAL);
        }
    
        @Test
        void shouldThrowExceptionWhenDeserializingOutOfRangeValue() {
            assertThatThrownBy(
                    () -> jsonConverter.readValue("{\"attachmentHint\": \"-1\"}", IntSerializationTestDTO.class)
            ).isInstanceOf(DataConversionException.class);
        }
    
        @Test
        void shouldThrowExceptionWhenDeserializingInvalidValue() {
            assertThatThrownBy(
                    () -> jsonConverter.readValue("{\"attachmentHint\": \"\"}", IntSerializationTestDTO.class)
            ).isInstanceOf(DataConversionException.class);
        }
    
        @Test
        void shouldDeserializeNullToNull() {
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
        void shouldSerializeToJsonString(){
            StringSerializationTestDTO dto = new StringSerializationTestDTO();
            dto.attachmentHint = AttachmentHint.INTERNAL;
            String string = jsonConverter.writeValueAsString(dto);
            assertThat(string).isEqualTo("{\"attachmentHint\":\"internal\"}");
        }
    
        @Test
        void shouldDeserializeFromJsonString() {
            StringSerializationTestDTO dto = jsonConverter.readValue("{\"attachmentHint\":\"internal\"}", StringSerializationTestDTO.class);
            assertThat(dto.attachmentHint).isEqualTo(AttachmentHint.INTERNAL);
        }
    
        @Test
        void shouldThrowExceptionWhenDeserializingInvalidString() {
            assertThatThrownBy(
                    () -> jsonConverter.readValue("{\"attachmentHint\": \"invalid\"}", StringSerializationTestDTO.class)
            ).isInstanceOf(DataConversionException.class);
        }
    
        @Test
        void shouldDeserializeNullToNull() {
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