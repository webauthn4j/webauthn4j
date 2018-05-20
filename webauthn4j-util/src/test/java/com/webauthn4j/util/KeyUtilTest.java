package com.webauthn4j.util;

import org.junit.Test;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import static org.assertj.core.api.Assertions.assertThat;

public class KeyUtilTest {

    @Test
    public void createKeyPair_test(){
        KeyPair keyPair = KeyUtil.createECKeyPair();
        assertThat(keyPair).isNotNull();
    }

    @Test
    public void createKeyPair_test_with_seed() throws NoSuchAlgorithmException {
        byte[] seed = new byte[]{0x01, 0x23, 0x45};
        KeyPair keyPairA = KeyUtil.createECKeyPair(seed);
        KeyPair keyPairB = KeyUtil.createECKeyPair(seed);
        assertThat(keyPairA.getPrivate().getEncoded()).isEqualTo(keyPairB.getPrivate().getEncoded());
    }
}
