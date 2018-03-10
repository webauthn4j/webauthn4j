package net.sharplab.springframework.security.webauthn.attestation.authenticator;

import net.sharplab.springframework.security.webauthn.test.CoreTestUtil;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test for RSCredentialPublicKey
 */
public class RSCredentialPublicKeyTest {

    @Test
    public void equals_test(){
        RSCredentialPublicKey instanceA = CoreTestUtil.createRSCredentialPublicKey();
        RSCredentialPublicKey instanceB = CoreTestUtil.createRSCredentialPublicKey();
        assertThat(instanceA).isEqualTo(instanceB);
    }
}
