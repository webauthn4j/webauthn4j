package net.sharplab.springframework.security.webauthn.attestation.authenticator;

import net.sharplab.springframework.security.webauthn.test.CoreTestUtil;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test for WebAuthnAuthenticatorData
 */
public class WebAuthnAuthenticatorDataTest {

    @Test
    public void flag_operation_test(){
        WebAuthnAuthenticatorData target = new WebAuthnAuthenticatorData();
        target.setFlagUP(true);
        assertThat(target.isFlagUP()).isTrue();
        target.setFlagUV(true);
        assertThat(target.isFlagUV()).isTrue();
        target.setFlagAT(true);
        assertThat(target.isFlagAT()).isTrue();
        target.setFlagED(true);
        assertThat(target.isFlagED()).isTrue();

        target.setFlagUP(false);
        assertThat(target.isFlagUP()).isFalse();
        target.setFlagUV(false);
        assertThat(target.isFlagUV()).isFalse();
        target.setFlagAT(false);
        assertThat(target.isFlagAT()).isFalse();
        target.setFlagED(false);
        assertThat(target.isFlagED()).isFalse();
    }

    @Test
    public void equals_test(){
        WebAuthnAuthenticatorData instanceA = CoreTestUtil.createWebAuthnAuthenticatorData();
        WebAuthnAuthenticatorData instanceB = CoreTestUtil.createWebAuthnAuthenticatorData();
        assertThat(instanceA).isEqualTo(instanceB);
    }

    @Test
    public void equals_test_with_not_equal_data(){
        WebAuthnAuthenticatorData instanceA = CoreTestUtil.createWebAuthnAuthenticatorData();
        WebAuthnAuthenticatorData instanceB = CoreTestUtil.createWebAuthnAuthenticatorData();
        instanceA.setFlagUP(false);
        instanceB.setFlagUP(true);
        assertThat(instanceA).isNotEqualTo(instanceB);
    }

    @Test
    public void hashCode_test(){
        WebAuthnAuthenticatorData instanceA = CoreTestUtil.createWebAuthnAuthenticatorData();
        WebAuthnAuthenticatorData instanceB = CoreTestUtil.createWebAuthnAuthenticatorData();
        assertThat(instanceA.hashCode()).isEqualTo(instanceB.hashCode());
    }

    @Test
    public void hashCode_test_with_not_equal_data(){
        WebAuthnAuthenticatorData instanceA = CoreTestUtil.createWebAuthnAuthenticatorData();
        WebAuthnAuthenticatorData instanceB = CoreTestUtil.createWebAuthnAuthenticatorData();
        instanceA.setCounter(1);
        instanceB.setCounter(2);
        assertThat(instanceA.hashCode()).isNotEqualTo(instanceB.hashCode());
    }


}
