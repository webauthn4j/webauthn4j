package com.webauthn4j.metadata.data.statement;

import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.util.UnsignedNumberUtil;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Java6Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("ResultOfMethodCallIgnored")
public class AttestationTypeTest {

    JsonConverter jsonConverter = new JsonConverter();

    @Test
    public void create_test() {
        assertAll(
                () -> assertThat(AttestationType.create(0x3E07)).isEqualTo(AttestationType.ATTESTATION_BASIC_FULL),
                () -> assertThat(AttestationType.create(0x3E08)).isEqualTo(AttestationType.ATTESTATION_BASIC_SURROGATE),
                () -> assertThat(AttestationType.create(0x3E09)).isEqualTo(AttestationType.ATTESTATION_ECDAA),
                () -> assertThat(AttestationType.create(0x3E0A)).isEqualTo(AttestationType.ATTESTATION_ATTCA)
        );
    }

    @Test
    public void create_test_with_value_over_upper_bound() {
        assertThrows(IllegalArgumentException.class,
                () -> AttestationType.create(UnsignedNumberUtil.UNSIGNED_SHORT_MAX + 1)
        );
    }

    @Test
    public void create_test_with_value_under_lower_bound() {
        assertThrows(IllegalArgumentException.class,
                () -> AttestationType.create(-1)
        );
    }

    @Test
    public void create_test_with_out_of_range_value() {
        assertThrows(IllegalArgumentException.class,
                () -> AttestationType.create(0x2A1D)
        );
    }

    @Test
    public void getValue_test() {
        assertAll(
                () -> assertThat(AttestationType.ATTESTATION_BASIC_FULL.getValue()).isEqualTo(0x3E07),
                () -> assertThat(AttestationType.ATTESTATION_BASIC_SURROGATE.getValue()).isEqualTo(0x3E08),
                () -> assertThat(AttestationType.ATTESTATION_ECDAA.getValue()).isEqualTo(0x3E09),
                () -> assertThat(AttestationType.ATTESTATION_ATTCA.getValue()).isEqualTo(0x3E0A)
        );
    }

    @Test
    public void fromInt_test() {
        TestDTO dto1 = jsonConverter.readValue("{\"attestation_type\":15879}", TestDTO.class);
        TestDTO dto2 = jsonConverter.readValue("{\"attestation_type\":15880}", TestDTO.class);
        TestDTO dto3 = jsonConverter.readValue("{\"attestation_type\":15881}", TestDTO.class);
        TestDTO dto4 = jsonConverter.readValue("{\"attestation_type\":15882}", TestDTO.class);

        assertAll(
                () -> assertThat(dto1.attestation_type).isEqualTo(AttestationType.ATTESTATION_BASIC_FULL),
                () -> assertThat(dto2.attestation_type).isEqualTo(AttestationType.ATTESTATION_BASIC_SURROGATE),
                () -> assertThat(dto3.attestation_type).isEqualTo(AttestationType.ATTESTATION_ECDAA),
                () -> assertThat(dto4.attestation_type).isEqualTo(AttestationType.ATTESTATION_ATTCA)
        );
    }

    @Test
    public void fromInt_test_with_invalid_value() {
        assertThrows(DataConversionException.class,
                () -> jsonConverter.readValue("{\"attestation_type\":123}", TestDTO.class)
        );
    }

    public static class TestDTO {
        public AttestationType attestation_type;
    }
}
