package com.webauthn4j.request;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import org.junit.Test;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

public class UserVerificationRequirementTest {

    private ObjectMapper objectMapper = new ObjectMapper();

    @Test
    public void create_test() {
        assertThat(UserVerificationRequirement.create("discouraged")).isEqualTo(UserVerificationRequirement.DISCOURAGED);
        assertThat(UserVerificationRequirement.create("preferred")).isEqualTo(UserVerificationRequirement.PREFERRED);
        assertThat(UserVerificationRequirement.create("required")).isEqualTo(UserVerificationRequirement.REQUIRED);
        assertThat(UserVerificationRequirement.create(null)).isEqualTo(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void create_test_with_invalid() {
        UserVerificationRequirement.create("invalid");
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

    @Test(expected = InvalidFormatException.class)
    public void fromString_test_with_invalid_value() throws IOException {
        objectMapper.readValue("{\"requirement\":\"invalid\"}", TestDTO.class);
    }

    public static class TestDTO{
        public UserVerificationRequirement requirement;
    }


}
