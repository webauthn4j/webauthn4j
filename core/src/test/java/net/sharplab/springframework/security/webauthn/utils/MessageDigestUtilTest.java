package net.sharplab.springframework.security.webauthn.utils;

import net.sharplab.springframework.security.webauthn.util.MessageDigestUtil;
import org.junit.Test;

import java.security.MessageDigest;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test for MessageDigestUtil
 */
public class MessageDigestUtilTest {

    @Test
    public void createMessageDigest_test(){
        MessageDigest s256 =  MessageDigestUtil.createMessageDigest("S256");
        MessageDigest s384 =  MessageDigestUtil.createMessageDigest("S384");
        MessageDigest s512 =  MessageDigestUtil.createMessageDigest("S512");

        MessageDigest sha256 =  MessageDigestUtil.createMessageDigest("SHA-256");

        assertThat(s256.getAlgorithm()).isEqualTo("SHA-256");
        assertThat(s384.getAlgorithm()).isEqualTo("SHA-384");
        assertThat(s512.getAlgorithm()).isEqualTo("SHA-512");
        assertThat(sha256.getAlgorithm()).isEqualTo("SHA-256");
    }

    @Test(expected = IllegalArgumentException.class)
    public void createMessageDigest_test_with_wrong_arg(){
        MessageDigest s256 =  MessageDigestUtil.createMessageDigest("wrong-arg");
    }

}
