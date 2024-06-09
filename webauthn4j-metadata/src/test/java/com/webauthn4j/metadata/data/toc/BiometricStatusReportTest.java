package com.webauthn4j.metadata.data.toc;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.assertj.core.api.Assertions.assertThat;

class BiometricStatusReportTest {

    @Test
    void constructor_test(){
        BiometricStatusReport biometricStatusReport = new BiometricStatusReport(0, BigInteger.ONE, "effectiveDataDummy", "certificationDescriptorDummy", "certificateNumberDummy", "certificatePolicyVersion", "certificateRequirementsVersionDummy");
        assertThat(biometricStatusReport.getCertLevel()).isZero();
        assertThat(biometricStatusReport.getModality()).isEqualTo(BigInteger.ONE);
        assertThat(biometricStatusReport.getEffectiveData()).isEqualTo("effectiveDataDummy");
        assertThat(biometricStatusReport.getCertificateNumber()).isEqualTo("certificateNumberDummy");
        assertThat(biometricStatusReport.getCertificationPolicyVersion()).isEqualTo("certificatePolicyVersion");
        assertThat(biometricStatusReport.getCertificationRequirementsVersion()).isEqualTo("certificateRequirementsVersionDummy");
    }

    @Test
    void equals_hashCode_test(){
        BiometricStatusReport instanceA = new BiometricStatusReport(0, BigInteger.ONE, "effectiveDataDummy", "certificationDescriptorDummy", "certificateNumberDummy", "certificatePolicyVersion", "certificateRequirementsVersionDummy");
        BiometricStatusReport instanceB = new BiometricStatusReport(0, BigInteger.ONE, "effectiveDataDummy", "certificationDescriptorDummy", "certificateNumberDummy", "certificatePolicyVersion", "certificateRequirementsVersionDummy");
        assertThat(instanceA)
                .isEqualTo(instanceB)
                .hasSameHashCodeAs(instanceB);
    }


}