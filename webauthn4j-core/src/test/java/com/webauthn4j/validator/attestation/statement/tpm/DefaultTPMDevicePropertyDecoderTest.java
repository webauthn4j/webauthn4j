package com.webauthn4j.validator.attestation.statement.tpm;

import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

class DefaultTPMDevicePropertyDecoderTest {

    private final DefaultTPMDevicePropertyDecoder target = new DefaultTPMDevicePropertyDecoder();

    @Test
    void parseTpmSAN_test_case1() throws IOException {
        String directoryName = "2.23.133.2.3=#0c0b69643a3030303230303030,2.23.133.2.2=#0c03535054,2.23.133.2.1=#0c0b69643a3439344535343433";
        TPMDeviceProperty tpmDeviceProperty = target.decode(directoryName);
        assertAll(
                () -> assertThat(tpmDeviceProperty.getManufacturer()).isEqualTo("id:494E5443"), // Intel
                () -> assertThat(tpmDeviceProperty.getPartNumber()).isEqualTo("SPT"),
                () -> assertThat(tpmDeviceProperty.getFirmwareVersion()).isEqualTo("id:00020000")
        );
    }

    @Test
    void parseTpmSAN_test_case2() throws IOException {
        String directoryName = "2.23.133.2.3=#0c0569643a3133+2.23.133.2.2=#0c074e504354367878+2.23.133.2.1=#0c0b69643a3445353434333030";
        TPMDeviceProperty tpmDeviceProperty = target.decode(directoryName);
        assertAll(
                () -> assertThat(tpmDeviceProperty.getManufacturer()).isEqualTo("id:4E544300"), // Nuvoton Technology
                () -> assertThat(tpmDeviceProperty.getPartNumber()).isEqualTo("NPCT6xx"),
                () -> assertThat(tpmDeviceProperty.getFirmwareVersion()).isEqualTo("id:13")
        );
    }

    @Test
    void parseTPMDeviceProperty_invalid_data_test() {
        assertThatThrownBy(() -> target.decode("hoge\"huga")).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void decodeAttr_null_test() throws IOException {
        assertThat(DefaultTPMDevicePropertyDecoder.decodeAttr(null)).isNull();
    }

}