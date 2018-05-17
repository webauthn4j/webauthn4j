package com.webauthn4j.attestation.authenticator;

import com.webauthn4j.attestation.statement.COSEAlgorithmIdentifier;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class ESSignatureAlgorithmTest {

    @Test
    public void create_test() {
        assertThat(COSEAlgorithmIdentifier.create(-7)).isEqualTo(COSEAlgorithmIdentifier.ES256);
        assertThat(COSEAlgorithmIdentifier.create(-35)).isEqualTo(COSEAlgorithmIdentifier.ES384);
        assertThat(COSEAlgorithmIdentifier.create(-36)).isEqualTo(COSEAlgorithmIdentifier.ES512);
    }

    @Test
    public void create_with_invalid_value_test() {
        //noinspection ResultOfMethodCallIgnored
        assertThatThrownBy(() -> COSEAlgorithmIdentifier.create(0)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    public void equals_test() {
        assertThat(COSEAlgorithmIdentifier.ES256).isEqualTo(COSEAlgorithmIdentifier.ES256);
        assertThat(COSEAlgorithmIdentifier.ES384).isNotEqualTo(COSEAlgorithmIdentifier.ES512);
    }


}
