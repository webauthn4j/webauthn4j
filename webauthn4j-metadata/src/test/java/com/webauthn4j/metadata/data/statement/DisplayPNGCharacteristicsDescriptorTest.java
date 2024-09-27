package com.webauthn4j.metadata.data.statement;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;

class DisplayPNGCharacteristicsDescriptorTest {

    @Test
    void constructor_test(){
        DisplayPNGCharacteristicsDescriptor displayPNGCharacteristicsDescriptor = new DisplayPNGCharacteristicsDescriptor(BigInteger.ZERO, BigInteger.ONE, (short)2, (short)3, (short)4, (short)5, (short)6, Collections.emptyList());
        assertThat(displayPNGCharacteristicsDescriptor.getWidth()).isEqualTo(BigInteger.ZERO);
        assertThat(displayPNGCharacteristicsDescriptor.getHeight()).isEqualTo(BigInteger.ONE);
        assertThat(displayPNGCharacteristicsDescriptor.getBitDepth()).isEqualTo((short) 2);
        assertThat(displayPNGCharacteristicsDescriptor.getColorType()).isEqualTo((short) 3);
        assertThat(displayPNGCharacteristicsDescriptor.getCompression()).isEqualTo((short) 4);
        assertThat(displayPNGCharacteristicsDescriptor.getFilter()).isEqualTo((short) 5);
        assertThat(displayPNGCharacteristicsDescriptor.getInterlace()).isEqualTo((short) 6);
        assertThat(displayPNGCharacteristicsDescriptor.getPlte()).isEqualTo(Collections.emptyList());
    }

    @Test
    void equals_hashCode_test(){
        DisplayPNGCharacteristicsDescriptor instanceA = new DisplayPNGCharacteristicsDescriptor(BigInteger.ZERO, BigInteger.ONE, (short)2, (short)3, (short)4, (short)5, (short)6, Collections.emptyList());
        DisplayPNGCharacteristicsDescriptor instanceB = new DisplayPNGCharacteristicsDescriptor(BigInteger.ZERO, BigInteger.ONE, (short)2, (short)3, (short)4, (short)5, (short)6, Collections.emptyList());
        assertThat(instanceA)
                .isEqualTo(instanceB)
                .hasSameHashCodeAs(instanceB);
    }

}