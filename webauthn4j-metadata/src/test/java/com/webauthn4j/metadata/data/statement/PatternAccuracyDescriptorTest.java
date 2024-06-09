package com.webauthn4j.metadata.data.statement;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.assertj.core.api.Assertions.assertThat;

class PatternAccuracyDescriptorTest {

    @Test
    void constructor_test(){
        PatternAccuracyDescriptor patternAccuracyDescriptor = new PatternAccuracyDescriptor(BigInteger.ZERO, 1, 2);
        assertThat(patternAccuracyDescriptor.getMinComplexity()).isEqualTo(BigInteger.ZERO);
        assertThat(patternAccuracyDescriptor.getMaxRetries()).isEqualTo(1);
        assertThat(patternAccuracyDescriptor.getBlockSlowdown()).isEqualTo(2);
    }

    @Test
    void equals_hashCode_test(){
        PatternAccuracyDescriptor instanceA = new PatternAccuracyDescriptor(BigInteger.ZERO, 1, 2);
        PatternAccuracyDescriptor instanceB = new PatternAccuracyDescriptor(BigInteger.ZERO, 1, 2);
        assertThat(instanceA)
                .isEqualTo(instanceB)
                .hasSameHashCodeAs(instanceB);
    }
}