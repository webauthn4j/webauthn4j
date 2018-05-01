package com.webauthn4j.attestation.authenticator;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class ESSignatureAlgorithmTest {

    @Test
    public void create_test(){
        assertThat(ESSignatureAlgorithm.create(-7)).isEqualTo(ESSignatureAlgorithm.SHA256withECDSA);
        assertThat(ESSignatureAlgorithm.create(-35)).isEqualTo(ESSignatureAlgorithm.SHA384withECDSA);
        assertThat(ESSignatureAlgorithm.create(-36)).isEqualTo(ESSignatureAlgorithm.SHA512withECDSA);
    }

    @Test
    public void create_with_invalid_value_test(){
        //noinspection ResultOfMethodCallIgnored
        assertThatThrownBy(() -> ESSignatureAlgorithm.create(0)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    public void equals_test(){
        assertThat(ESSignatureAlgorithm.SHA256withECDSA).isEqualTo(ESSignatureAlgorithm.SHA256withECDSA);
        assertThat(ESSignatureAlgorithm.SHA384withECDSA).isNotEqualTo(ESSignatureAlgorithm.SHA512withECDSA);
    }



}
