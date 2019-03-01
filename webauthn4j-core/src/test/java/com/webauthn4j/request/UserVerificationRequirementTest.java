package com.webauthn4j.request;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class UserVerificationRequirementTest {

    private ObjectMapper objectMapper = new ObjectMapper();

    @Test
    public void create_test() {
        assertAll(
                () -> assertThat(UserVerificationRequirement.create("discouraged")).isEqualTo(UserVerificationRequirement.DISCOURAGED),
                () -> assertThat(UserVerificationRequirement.create("preferred")).isEqualTo(UserVerificationRequirement.PREFERRED),
                () -> assertThat(UserVerificationRequirement.create("required")).isEqualTo(UserVerificationRequirement.REQUIRED),
                () -> assertThat(UserVerificationRequirement.create(null)).isEqualTo(null)
        );
    }

    @Test
    public void create_test_with_invalid() {
        assertThrows(IllegalArgumentException.class,
                () -> UserVerificationRequirement.create("invalid")
        );
    }

    @Test
    public void getValue() {
        assertThat(UserVerificationRequirement.REQUIRED.getValue()).isEqualTo("required");
    }

    @Test
    public void fromString_test() throws IOException {
        TestDTO dto = objectMapper.readValue("{\"requirement\":\"required\"}", TestDTO.class);
        assertThat(dto.requirement).isEqualTo(UserVerificationRequirement.REQUIRED);
    }

    @Test
    public void fromString_test_with_invalid_value() {
        assertThrows(InvalidFormatException.class,
                () -> objectMapper.readValue("{\"requirement\":\"invalid\"}", TestDTO.class)
        );
    }

    public static class TestDTO {
        public UserVerificationRequirement requirement;
    }
}
