package com.webauthn4j.data;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.List;

import static org.assertj.core.api.Assertions.*;
import static org.assertj.core.api.Assertions.assertThat;

class PublicKeyCredentialHintsTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void test() throws IOException {
        TestDto testDto = objectMapper.readValue("{\"hints\": [\"security-key\"]}", TestDto.class);
        assertThat(testDto.getHints()).containsExactly(PublicKeyCredentialHints.SECURITY_KEY);
    }

    @Test
    void null_test() throws IOException {
        TestDto testDto = objectMapper.readValue("{\"hints\": null}", TestDto.class);
        assertThat(testDto.getHints()).isNull();
    }

    @Test
    void create_test() {
        PublicKeyCredentialHints value = PublicKeyCredentialHints.create("hybrid");
        assertThat(value).isEqualTo(PublicKeyCredentialHints.HYBRID);
    }

    @Test
    void create_null_test() {
        assertThatThrownBy(() -> PublicKeyCredentialHints.create(null)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void unknown_data_test() {
        assertThatCode(
                () -> objectMapper.readValue("{\"hints\": [\"unknown-data\"]}", TestDto.class)
        ).doesNotThrowAnyException();
    }

    @Test
    void equals_hashCode_test(){
        assertThat(PublicKeyCredentialHints.create("unknown")).isEqualTo(PublicKeyCredentialHints.create("unknown"));
        assertThat(PublicKeyCredentialHints.create("client-device")).isEqualTo(PublicKeyCredentialHints.CLIENT_DEVICE);
        assertThat(PublicKeyCredentialHints.create("client-device")).hasSameHashCodeAs(PublicKeyCredentialHints.CLIENT_DEVICE);
    }

    @Test
    void getValue_test(){
        assertThat(PublicKeyCredentialHints.CLIENT_DEVICE.getValue()).isEqualTo("client-device");
    }

    @Test
    void toString_test(){
        assertThat(PublicKeyCredentialHints.CLIENT_DEVICE).asString().isEqualTo("client-device");
    }

    static class TestDto{
        @JsonProperty
        private List<PublicKeyCredentialHints> hints;

        public List<PublicKeyCredentialHints>  getHints() {
            return hints;
        }

        public void setHints(List<PublicKeyCredentialHints> hints) {
            this.hints = hints;
        }
    }


}