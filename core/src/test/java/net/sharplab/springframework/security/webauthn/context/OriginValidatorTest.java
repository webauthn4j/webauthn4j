package net.sharplab.springframework.security.webauthn.context;

import net.sharplab.springframework.security.webauthn.client.ClientData;
import net.sharplab.springframework.security.webauthn.client.Origin;
import net.sharplab.springframework.security.webauthn.context.validator.OriginValidator;
import net.sharplab.springframework.security.webauthn.exception.BadOriginException;
import net.sharplab.springframework.security.webauthn.test.CoreTestUtil;
import org.junit.Test;

/**
 * Test for OriginValidator
 */
public class OriginValidatorTest {

    private OriginValidator target = new OriginValidator();

    @Test
    public void test(){
        Origin originA = new Origin("https://example.com:14443");
        Origin originB = new Origin("https://example.com:14443");

        ClientData clientData = CoreTestUtil.createClientData();
        clientData.setOrigin(originA);
        RelyingParty relyingParty = new RelyingParty(originB, "example.com", CoreTestUtil.createChallenge());
        target.validate(clientData, relyingParty);
    }

    @Test(expected = BadOriginException.class)
    public void test_with_not_equal_origins(){
        Origin originA = new Origin("https://example.com:14443");
        Origin originB = new Origin("http://example.com");

        ClientData clientData = CoreTestUtil.createClientData();
        clientData.setOrigin(originA);
        RelyingParty relyingParty = new RelyingParty(originB, "example.com", CoreTestUtil.createChallenge());
        target.validate(clientData, relyingParty);
    }

}
