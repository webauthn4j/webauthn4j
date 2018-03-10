package net.sharplab.springframework.security.webauthn.context.validator;

import net.sharplab.springframework.security.webauthn.client.Origin;
import net.sharplab.springframework.security.webauthn.exception.BadOriginException;
import net.sharplab.springframework.security.webauthn.context.RelyingParty;
import net.sharplab.springframework.security.webauthn.client.ClientData;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.core.SpringSecurityMessageSource;

import java.util.Objects;

/**
 * Validates {@link Origin} instance
 */
public class OriginValidator {

    protected final Log logger = LogFactory.getLog(getClass());
    protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

    public void validate(ClientData clientData, RelyingParty relyingParty) {
        if (!Objects.equals(clientData.getOrigin(), relyingParty.getOrigin())) {
            logger.debug("Authentication failed: bad origin is specified");
            throw new BadOriginException(messages.getMessage("OriginValidator.badOrigin", "Bad origin"));
        }
    }
}
