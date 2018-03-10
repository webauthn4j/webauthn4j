package net.sharplab.springframework.security.webauthn.context.validator;

import net.sharplab.springframework.security.webauthn.exception.BadRpIdException;
import net.sharplab.springframework.security.webauthn.context.RelyingParty;
import net.sharplab.springframework.security.webauthn.util.MessageDigestUtil;
import org.junit.Test;

import java.nio.charset.StandardCharsets;

/**
 * Created by ynojima on 2017/08/27.
 */
public class RpIdHashValidatorTest {

    private RpIdHashValidator target = new RpIdHashValidator();

    @Test
    public void verifyRpIdHash_test(){

        String rpIdA = "example.com";
        String rpIdB = "example.com";
        byte[] rpIdBytesA = rpIdA.getBytes(StandardCharsets.UTF_8);
        byte[] rpIdHashA = MessageDigestUtil.createMessageDigest("S256").digest(rpIdBytesA);

        RelyingParty relyingParty = new RelyingParty(null, rpIdB, null);

        //When
        target.validate(rpIdHashA, relyingParty);
    }

    @Test(expected = BadRpIdException.class)
    public void verifyRpIdHash_test_with_different_rpIds(){

        String rpIdA = "sub.example.com";
        String rpIdB = "example.com";
        byte[] rpIdBytesA = rpIdA.getBytes(StandardCharsets.UTF_8);
        byte[] rpIdHashA = MessageDigestUtil.createMessageDigest("S256").digest(rpIdBytesA);

        RelyingParty relyingParty = new RelyingParty(null, rpIdB, null);

        //When
        target.validate(rpIdHashA, relyingParty);
    }

}
