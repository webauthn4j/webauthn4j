package net.sharplab.springframework.security.webauthn.context.validator.assertion.signature;

import net.sharplab.springframework.security.webauthn.attestation.authenticator.AbstractCredentialPublicKey;
import net.sharplab.springframework.security.webauthn.context.WebAuthnAuthenticationContext;
import net.sharplab.springframework.security.webauthn.exception.BadSignatureException;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.core.SpringSecurityMessageSource;

/**
 * AbstractAssertionSignatureValidator
 */
public abstract class AbstractAssertionSignatureValidator implements AssertionSignatureValidator {

    protected final MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

    @Override
    public void verifySignature(WebAuthnAuthenticationContext webAuthnAuthenticationContext, AbstractCredentialPublicKey credentialPublicKey) {
        byte[] signedData = getSignedData(webAuthnAuthenticationContext);
        byte[] signature = webAuthnAuthenticationContext.getSignature();
        if (!credentialPublicKey.verifySignature(signature, signedData)) {
            throw new BadSignatureException(messages.getMessage("AbstractAssertionSignatureValidator.BadSignature", "Bad signature"));
        }
    }

    protected abstract byte[] getSignedData(WebAuthnAuthenticationContext webAuthnAuthenticationContext);
}
