package com.webauthn4j.converter.jackson;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.statement.TPMISTAttest;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThatCode;

class ByteArrayBase64ConverterModuleTest {

    @Test
    void test(){
        ObjectConverter objectConverter = new ObjectConverter();
        JsonConverter jsonConverter = objectConverter.getJsonConverter();
        jsonConverter.registerModule(new ByteArrayBase64ConverterModule());

        byte[] source = TPMISTAttest.TPM_ST_ATTEST_CERTIFY.getValue();
        String sourceString = "{\"tpmi_st_attest\":\"" + Base64.getEncoder().encodeToString(source) + "\"}";
        assertThatCode(() -> jsonConverter.readValue(sourceString, TestDTO.class)).doesNotThrowAnyException();
    }

    static class TestDTO {
        @JsonProperty("tpmi_st_attest")
        public TPMISTAttest tpmiStAttest;
    }
}