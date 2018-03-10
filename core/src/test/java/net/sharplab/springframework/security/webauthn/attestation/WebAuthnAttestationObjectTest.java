package net.sharplab.springframework.security.webauthn.attestation;

import net.sharplab.springframework.security.webauthn.test.CoreTestUtil;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Created by ynojima on 2017/08/19.
 */
public class WebAuthnAttestationObjectTest {

    @Test
    public void equals_test(){
        WebAuthnAttestationObject instanceA = CoreTestUtil.createWebAuthnAttestationObjectWithFIDOU2FAttestationStatement();
        WebAuthnAttestationObject instanceB = CoreTestUtil.createWebAuthnAttestationObjectWithFIDOU2FAttestationStatement();
        assertThat(instanceA).isEqualTo(instanceB);
    }
}
