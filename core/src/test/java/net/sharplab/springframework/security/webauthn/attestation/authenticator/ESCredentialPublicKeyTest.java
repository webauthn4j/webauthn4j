package net.sharplab.springframework.security.webauthn.attestation.authenticator;

import net.sharplab.springframework.security.webauthn.test.CoreTestUtil;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test for ESCredentialPublicKey
 */
public class ESCredentialPublicKeyTest {

    @Test
    public void equals_test(){
        ESCredentialPublicKey instanceA = CoreTestUtil.createESCredentialPublicKey();
        ESCredentialPublicKey instanceB = CoreTestUtil.createESCredentialPublicKey();
        assertThat(instanceA).isEqualTo(instanceB);
    }
}
