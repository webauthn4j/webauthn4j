package net.sharplab.springframework.security.webauthn.context.validator;

import net.sharplab.springframework.security.webauthn.exception.BadChallengeException;
import net.sharplab.springframework.security.webauthn.exception.MissingChallengeException;
import net.sharplab.springframework.security.webauthn.context.RelyingParty;
import net.sharplab.springframework.security.webauthn.client.ClientData;
import net.sharplab.springframework.security.webauthn.client.challenge.Challenge;
import net.sharplab.springframework.security.webauthn.client.challenge.DefaultChallenge;
import org.junit.Test;

/**
 * Test for ChallengeValidator
 */
public class ChallengeValidatorTest {

    private ChallengeValidator target = new ChallengeValidator();

    @Test
    public void verifyChallenge_test1(){

        Challenge challengeA = new DefaultChallenge(new byte[]{0x00});
        Challenge challengeB = new DefaultChallenge(new byte[]{0x00});

        ClientData clientData = new ClientData();
        clientData.setChallenge(challengeA);
        RelyingParty relyingParty = new RelyingParty(null, null, challengeB);

        //When
        target.validate(clientData, relyingParty);
    }

    @Test(expected = BadChallengeException.class)
    public void verifyChallenge_test_with_different_challenge(){

        Challenge challengeA = new DefaultChallenge(new byte[]{0x00});
        Challenge challengeB = new DefaultChallenge(new byte[]{0x01});

        ClientData clientData = new ClientData();
        clientData.setChallenge(challengeA);
        RelyingParty relyingParty = new RelyingParty(null, null, challengeB);

        //When
        target.validate(clientData, relyingParty);
    }

    @Test(expected = MissingChallengeException.class)
    public void verifyChallenge_test_without_saved_challenge(){

        Challenge challengeA = new DefaultChallenge(new byte[]{0x00});
        Challenge challengeB = null;

        ClientData clientData = new ClientData();
        clientData.setChallenge(challengeA);
        RelyingParty relyingParty = new RelyingParty(null, null, challengeB);

        //When
        target.validate(clientData, relyingParty);
    }
}
