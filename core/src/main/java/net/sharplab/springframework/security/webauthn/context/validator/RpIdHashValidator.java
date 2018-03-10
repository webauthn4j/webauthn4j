package net.sharplab.springframework.security.webauthn.context.validator;

import net.sharplab.springframework.security.webauthn.exception.BadRpIdException;
import net.sharplab.springframework.security.webauthn.context.RelyingParty;
import net.sharplab.springframework.security.webauthn.util.MessageDigestUtil;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.core.SpringSecurityMessageSource;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * Validates rpIdHash
 */
public class    RpIdHashValidator {

    protected final Log logger = LogFactory.getLog(getClass());
    protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();


    public void validate(byte[] rpIdHash, RelyingParty relyingParty) {
        MessageDigest messageDigest = MessageDigestUtil.createMessageDigest("S256");
        byte[] relyingPartyRpIdBytes = relyingParty.getRpId().getBytes(StandardCharsets.UTF_8);
        byte[] relyingPartyRpIdHash = messageDigest.digest(relyingPartyRpIdBytes);
        if(!Arrays.equals(rpIdHash, relyingPartyRpIdHash)){
            logger.debug("Authentication failed: bad rpId is specified");
            throw new BadRpIdException(messages.getMessage("WebAuthnAuthenticationProvider.badRpId", "Bad rpId"));
        }
    }
}
