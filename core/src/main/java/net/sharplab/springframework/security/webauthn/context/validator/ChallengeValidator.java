package net.sharplab.springframework.security.webauthn.context.validator;

import net.sharplab.springframework.security.webauthn.exception.BadChallengeException;
import net.sharplab.springframework.security.webauthn.exception.MissingChallengeException;
import net.sharplab.springframework.security.webauthn.context.RelyingParty;
import net.sharplab.springframework.security.webauthn.client.ClientData;
import net.sharplab.springframework.security.webauthn.client.challenge.Challenge;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.core.SpringSecurityMessageSource;

import java.util.Arrays;

/**
 * Validates {@link Challenge} instance
 */
public class ChallengeValidator {

    protected final Log logger = LogFactory.getLog(getClass());
    protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();


    public void validate(ClientData clientData, RelyingParty relyingParty){
        Challenge savedChallenge = relyingParty.getChallenge();
        if (savedChallenge == null) {
            logger.debug("Authentication failed: challenge is not stored in the challenge repository");
            throw new MissingChallengeException(messages.getMessage(
                    "ChallengeValidator.missingChallenge",
                    "Missing challenge"));
        }
        byte[] savedChallengeValue = savedChallenge.getValue();

        byte[] challengeValueInClientData = clientData.getChallenge().getValue();

        // Verify that the challenge member of the clientData matches the challenge that was sent to
        // the authenticator in the PublicKeyCredentialRequestOptions passed to the get() call.
        if (!Arrays.equals(challengeValueInClientData, savedChallengeValue)) {
            logger.debug("Authentication failed: bad challenge is specified");
            throw new BadChallengeException(messages.getMessage(
                    "ChallengeValidator.badChallenge",
                    "Bad challenge"));
        }
    }
}
