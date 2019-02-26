package com.webauthn4j.metadata.data.statement;

import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.util.UnsignedNumberUtil;

import org.junit.Test;

import static org.assertj.core.api.Java6Assertions.assertThat;

@SuppressWarnings("ResultOfMethodCallIgnored")
public class AttestationTypeTest {

    JsonConverter jsonConverter = new JsonConverter();

    @Test
    public void create_test() {
        assertThat(AttestationType.create(0x3E07)).isEqualTo(AttestationType.ATTESTATION_BASIC_FULL);
        assertThat(AttestationType.create(0x3E08)).isEqualTo(AttestationType.ATTESTATION_BASIC_SURROGATE);
        assertThat(AttestationType.create(0x3E09)).isEqualTo(AttestationType.ATTESTATION_ECDAA);
        assertThat(AttestationType.create(0x3E0A)).isEqualTo(AttestationType.ATTESTATION_ATTCA);
    }

    @Test(expected = IllegalArgumentException.class)
    public void create_test_with_value_over_upper_bound() {
        AttestationType.create(UnsignedNumberUtil.UNSIGNED_SHORT_MAX + 1);
    }

    @Test(expected = IllegalArgumentException.class)
    public void create_test_with_value_under_lower_bound() {
        AttestationType.create(-1);
    }

    @Test(expected = IllegalArgumentException.class)
    public void create_test_with_out_of_range_value() {
        AttestationType.create(0x2A1D);
    }

    @Test
    public void getValue_test() {
        assertThat(AttestationType.ATTESTATION_BASIC_FULL.getValue()).isEqualTo(0x3E07);
        assertThat(AttestationType.ATTESTATION_BASIC_SURROGATE.getValue()).isEqualTo(0x3E08);
        assertThat(AttestationType.ATTESTATION_ECDAA.getValue()).isEqualTo(0x3E09);
        assertThat(AttestationType.ATTESTATION_ATTCA.getValue()).isEqualTo(0x3E0A);
    }

    @Test
    public void fromInt_test() {
        TestDTO dto = jsonConverter.readValue("{\"attestation_type\":15879}", TestDTO.class);
        assertThat(dto.attestation_type).isEqualTo(AttestationType.ATTESTATION_BASIC_FULL);
        dto = jsonConverter.readValue("{\"attestation_type\":15880}", TestDTO.class);
        assertThat(dto.attestation_type).isEqualTo(AttestationType.ATTESTATION_BASIC_SURROGATE);
        dto = jsonConverter.readValue("{\"attestation_type\":15881}", TestDTO.class);
        assertThat(dto.attestation_type).isEqualTo(AttestationType.ATTESTATION_ECDAA);
        dto = jsonConverter.readValue("{\"attestation_type\":15882}", TestDTO.class);
        assertThat(dto.attestation_type).isEqualTo(AttestationType.ATTESTATION_ATTCA);
    }

    @Test(expected = DataConversionException.class)
    public void fromInt_test_with_invalid_value() {
        jsonConverter.readValue("{\"attestation_type\":123}", TestDTO.class);
    }

    public static class TestDTO {
        public AttestationType attestation_type;
    }
}
