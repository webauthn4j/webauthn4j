package com.webauthn4j.request;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;

class UserVerificationRequirementTest {

    private ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void create_test() {
        assertAll(
                () -> assertThat(UserVerificationRequirement.create("discouraged")).isEqualTo(UserVerificationRequirement.DISCOURAGED),
                () -> assertThat(UserVerificationRequirement.create("preferred")).isEqualTo(UserVerificationRequirement.PREFERRED),
                () -> assertThat(UserVerificationRequirement.create("required")).isEqualTo(UserVerificationRequirement.REQUIRED),
                () -> assertThat(UserVerificationRequirement.create(null)).isEqualTo(null)
        );
    }

    @Test
    void create_test_with_invalid() {
        assertThrows(IllegalArgumentException.class,
                () -> UserVerificationRequirement.create("invalid")
        );
    }

    @Test
    void getValue() {
        assertThat(UserVerificationRequirement.REQUIRED.getValue()).isEqualTo("required");
    }

    @Test
    void fromString_test() throws IOException {
        TestDTO dto = objectMapper.readValue("{\"requirement\":\"required\"}", TestDTO.class);
        assertThat(dto.requirement).isEqualTo(UserVerificationRequirement.REQUIRED);
    }

    @Test
    void fromString_test_with_invalid_value() {
        assertThrows(InvalidFormatException.class,
                () -> objectMapper.readValue("{\"requirement\":\"invalid\"}", TestDTO.class)
        );
    }

    static class TestDTO {
        @SuppressWarnings("WeakerAccess")
        public UserVerificationRequirement requirement;
    }
}
