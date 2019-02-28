package com.webauthn4j.request;

import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.JsonConverter;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Java6Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("ResultOfMethodCallIgnored")
public class AttestationConveyancePreferenceTest {

    JsonConverter jsonConverter = new JsonConverter();

    @Test
    public void create_test() {
        assertAll(
                () -> assertThat(AttestationConveyancePreference.create("none")).isEqualTo(AttestationConveyancePreference.NONE),
                () -> assertThat(AttestationConveyancePreference.create("direct")).isEqualTo(AttestationConveyancePreference.DIRECT),
                () -> assertThat(AttestationConveyancePreference.create("indirect")).isEqualTo(AttestationConveyancePreference.INDIRECT)
        );
    }

    @Test
    public void create_test_with_null_value() {
        assertThat(AttestationConveyancePreference.create(null)).isEqualTo(null);
    }

    @Test
    public void create_test_with_invalid_value() {
        assertThrows(IllegalArgumentException.class,
                () -> AttestationConveyancePreference.create("invalid")
        );
    }

    @Test
    public void getValue_test() {
        assertAll(
                () -> assertThat(AttestationConveyancePreference.NONE.getValue()).isEqualTo("none"),
                () -> assertThat(AttestationConveyancePreference.DIRECT.getValue()).isEqualTo("direct"),
                () -> assertThat(AttestationConveyancePreference.INDIRECT.getValue()).isEqualTo("indirect")
        );
    }

    @Test
    public void fromString_test() {
        TestDTO dto = jsonConverter.readValue("{\"preference\":\"none\"}", TestDTO.class);
        assertThat(dto.preference).isEqualTo(AttestationConveyancePreference.NONE);
    }

    @Test
    public void fromString_test_with_invalid_value() {
        assertThrows(DataConversionException.class,
                () -> jsonConverter.readValue("{\"preference\":\"invalid\"}", TestDTO.class)
        );
    }

    public static class TestDTO{
        public AttestationConveyancePreference preference;
    }
}