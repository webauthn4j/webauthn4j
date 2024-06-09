package com.webauthn4j.metadata.data.statement;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ExtensionDescriptorTest {

    @Test
    void constructor_test(){
        ExtensionDescriptor extensionDescriptor = new ExtensionDescriptor("idDummy", 0, "dataDummy", false);
        assertThat(extensionDescriptor.getId()).isEqualTo("idDummy");
        assertThat(extensionDescriptor.getTag()).isZero();
        assertThat(extensionDescriptor.getData()).isEqualTo("dataDummy");
        assertThat(extensionDescriptor.getFailIfUnknown()).isFalse();
    }

    @Test
    void equals_hashCode_test(){
        ExtensionDescriptor instanceA = new ExtensionDescriptor("idDummy", 0, "dataDummy", false);
        ExtensionDescriptor instanceB = new ExtensionDescriptor("idDummy", 0, "dataDummy", false);
        assertThat(instanceA)
                .isEqualTo(instanceB)
                .hasSameHashCodeAs(instanceB);
    }
}
