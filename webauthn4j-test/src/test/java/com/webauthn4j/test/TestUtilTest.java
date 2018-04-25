package com.webauthn4j.test;

import org.junit.Test;

import java.security.PrivateKey;

import static org.assertj.core.api.Assertions.assertThat;

public class TestUtilTest {

    @Test
    public void loadTestAuthenticatorAttestationPrivateKey_test(){
        PrivateKey privateKey = TestUtil.loadTestAuthenticatorAttestationPrivateKey();
        assertThat(privateKey).isNotNull();
    }
}
