package net.sharplab.springframework.security.webauthn.attestation.authenticator;

import net.sharplab.springframework.security.webauthn.test.CoreTestUtil;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Created by ynojima on 2017/08/19.
 */
public class WebAuthnAttestedCredentialDataTest {

    @Test
    public void equals_test(){
        WebAuthnAttestedCredentialData instanceA = CoreTestUtil.createWebAuthnAttestedCredentialData();
        WebAuthnAttestedCredentialData instanceB = CoreTestUtil.createWebAuthnAttestedCredentialData();
        assertThat(instanceA).isEqualTo(instanceB);
    }
}
