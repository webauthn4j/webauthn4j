package com.webauthn4j.metadata.data.statement;


import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class BiometricAccuracyDescriptorTest {

    @Test
    void constructor_test(){
        BiometricAccuracyDescriptor biometricAccuracyDescriptor = new BiometricAccuracyDescriptor(1.0, 0.0, 0.5, 2, 3, 4);
        assertThat(biometricAccuracyDescriptor.getSelfAttestedFRR()).isEqualTo(1.0);
        assertThat(biometricAccuracyDescriptor.getSelfAttestedFAR()).isEqualTo(0.0);
        assertThat(biometricAccuracyDescriptor.getIAPARThreshold()).isEqualTo(0.5);
        assertThat(biometricAccuracyDescriptor.getMaxTemplates()).isEqualTo(2);
        assertThat(biometricAccuracyDescriptor.getMaxRetries()).isEqualTo(3);
        assertThat(biometricAccuracyDescriptor.getBlockSlowdown()).isEqualTo(4);
    }

    @SuppressWarnings("deprecation")
    @Test
    void deprecated_constructor_and_getMaxTemplate_test(){
        BiometricAccuracyDescriptor descriptor = new BiometricAccuracyDescriptor(0.0, 1.0, 2, 3, 4);
        assertThat(descriptor.getIAPARThreshold()).isNull();
        assertThat(descriptor.getMaxTemplate()).isEqualTo(2);
        assertThat(descriptor.getMaxTemplates()).isEqualTo(2);
    }

    @Test
    void equals_hashCode_test(){
        BiometricAccuracyDescriptor instanceA = new BiometricAccuracyDescriptor(1.0, 0.0, 0.5, 2, 3, 4);
        BiometricAccuracyDescriptor instanceB = new BiometricAccuracyDescriptor(1.0, 0.0, 0.5, 2, 3, 4);
        assertThat(instanceA)
                .isEqualTo(instanceB)
                .hasSameHashCodeAs(instanceB);
    }

}