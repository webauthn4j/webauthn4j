package net.sharplab.springframework.security.webauthn.context.validator;

import net.sharplab.springframework.security.webauthn.WebAuthnAssertionAuthenticationToken;
import net.sharplab.springframework.security.webauthn.attestation.authenticator.AbstractCredentialPublicKey;
import net.sharplab.springframework.security.webauthn.attestation.authenticator.WebAuthnAuthenticatorData;
import net.sharplab.springframework.security.webauthn.authenticator.WebAuthnAuthenticator;
import net.sharplab.springframework.security.webauthn.client.ClientData;
import net.sharplab.springframework.security.webauthn.context.RelyingParty;
import net.sharplab.springframework.security.webauthn.context.WebAuthnAuthenticationContext;
import net.sharplab.springframework.security.webauthn.context.validator.assertion.signature.AssertionSignatureValidator;
import net.sharplab.springframework.security.webauthn.exception.UserNotVerifiedException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.FirstOfMultiFactorAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.SpringSecurityMessageSource;

import java.util.List;

/**
 * Validates {@link WebAuthnAuthenticationContext} instance
 */
public class WebAuthnAuthenticationContextValidator {

    //~ Instance fields
    // ================================================================================================
    protected final Log logger = LogFactory.getLog(getClass());
    protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

    private ChallengeValidator challengeValidator = new ChallengeValidator();
    private OriginValidator originValidator = new OriginValidator();
    private RpIdHashValidator rpIdHashValidator = new RpIdHashValidator();

    private List<AssertionSignatureValidator> assertionSignatureValidators;

    public WebAuthnAuthenticationContextValidator(List<AssertionSignatureValidator> assertionSignatureValidators){
        this.assertionSignatureValidators = assertionSignatureValidators;
    }

    public void validate(WebAuthnAuthenticator webAuthnAuthenticator, WebAuthnAssertionAuthenticationToken authenticationToken){

        if (authenticationToken.getCredentials() == null) {
            logger.debug("Authentication failed: no credentials provided");

            throw new BadCredentialsException(messages.getMessage(
                    "WebAuthnAuthenticationProvider.badCredentials",
                    "Bad credentials"));
        }

        WebAuthnAuthenticationContext webAuthnAuthenticationContext = authenticationToken.getCredentials();
        AbstractCredentialPublicKey credentialPublicKey = webAuthnAuthenticator.getAttestationData().getCredentialPublicKey();
        String username = webAuthnAuthenticator.getUser().getUsername();

        RelyingParty relyingParty = webAuthnAuthenticationContext.getRelyingParty();
        ClientData clientData = webAuthnAuthenticationContext.getClientData();
        WebAuthnAuthenticatorData authenticatorData = webAuthnAuthenticationContext.getAuthenticatorData();

        verifyUserVerified(webAuthnAuthenticationContext, username);

        // Verify that the challenge member of C matches the challenge that was sent to the authenticator
        // in the PublicKeyCredentialRequestOptions passed to the get() call.
        challengeValidator.validate(clientData, relyingParty);

        // Verify that the origin member of the clientData matches the Relying Party's origin.
        originValidator.validate(clientData, relyingParty);

        // Verify that the tokenBindingId member of the clientData (if present) matches the Token Binding ID for
        // the TLS connection over which the signature was obtained.
        //TODO: not yet implemented

        // Verify that the clientExtensions member of the clientData is a proper subset of the extensions
        // requested by the Relying Party and that the authenticatorExtensions in the clientData is also
        // a proper subset of the extensions requested by the Relying Party.
        // TODO: not yet implemented

        // Verify that the RP ID hash in the authenticatorData is the SHA-256 hash of the RP ID
        // expected by the Relying Party.
        rpIdHashValidator.validate(authenticatorData.getRpIdHash(), relyingParty);

        // Using the credential public key, validate that sig is a valid signature over
        // the binary concatenation of the authenticatorData and the hash of the clientData.
        verifyAssertionSignature(webAuthnAuthenticator, webAuthnAuthenticationContext, credentialPublicKey);
    }

    void verifyAssertionSignature(WebAuthnAuthenticator webAuthnAuthenticator, WebAuthnAuthenticationContext webAuthnAuthenticationContext, AbstractCredentialPublicKey credentialPublicKey) {
        for (AssertionSignatureValidator assertionSignatureValidator : assertionSignatureValidators) {
            if( assertionSignatureValidator.supports(webAuthnAuthenticator.getFormat())){
                assertionSignatureValidator.verifySignature(webAuthnAuthenticationContext, credentialPublicKey);
                return;
            }
        }

        logger.debug("Authentication failed: publicKey does not match stored value");
        throw new BadCredentialsException(messages.getMessage(
                "WebAuthnAuthenticationProvider.badCredentials",
                "Bad credentials"));
    }

    void verifyUserVerified(WebAuthnAuthenticationContext webAuthnAuthenticationContext, String username){
        if (webAuthnAuthenticationContext.getAuthenticatorData().isFlagUV()) {
            return;
        }
        Authentication currentAuthentication = webAuthnAuthenticationContext.getCurrentAuthentication();
        if (isFirstOfMFAPassedUser(currentAuthentication, username)) {
            return;
        }
        throw new UserNotVerifiedException(messages.getMessage(
                "WebAuthnAuthenticationProvider.userNotVerified",
                "User not verified"));
    }

    boolean isFirstOfMFAPassedUser(Authentication authentication, String username){
        return authentication instanceof FirstOfMultiFactorAuthenticationToken
                && username.equals(authentication.getName());
    }

}
