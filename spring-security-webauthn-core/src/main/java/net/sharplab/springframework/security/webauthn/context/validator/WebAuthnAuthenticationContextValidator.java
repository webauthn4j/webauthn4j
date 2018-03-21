/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.sharplab.springframework.security.webauthn.context.validator;

import com.webauthn4j.webauthn.context.RelyingParty;
import com.webauthn4j.webauthn.context.WebAuthnAuthenticationContext;
import com.webauthn4j.webauthn.context.validator.ChallengeValidator;
import com.webauthn4j.webauthn.context.validator.OriginValidator;
import com.webauthn4j.webauthn.context.validator.RpIdHashValidator;
import com.webauthn4j.webauthn.context.validator.assertion.signature.AssertionSignatureValidator;
import net.sharplab.springframework.security.webauthn.WebAuthnAssertionAuthenticationToken;
import com.webauthn4j.webauthn.attestation.authenticator.AbstractCredentialPublicKey;
import com.webauthn4j.webauthn.attestation.authenticator.WebAuthnAuthenticatorData;
import net.sharplab.springframework.security.webauthn.authenticator.WebAuthnAuthenticator;
import com.webauthn4j.webauthn.client.CollectedClientData;
import com.webauthn4j.webauthn.exception.UserNotVerifiedException;
import net.sharplab.springframework.security.webauthn.exception.BadChallengeException;
import net.sharplab.springframework.security.webauthn.exception.BadOriginException;
import net.sharplab.springframework.security.webauthn.exception.BadRpIdException;
import net.sharplab.springframework.security.webauthn.exception.BadSignatureException;
import net.sharplab.springframework.security.webauthn.userdetails.WebAuthnUserDetails;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.FirstOfMultiFactorAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.context.SecurityContextHolder;

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

    public WebAuthnAuthenticationContextValidator(List<AssertionSignatureValidator> assertionSignatureValidators) {
        this.assertionSignatureValidators = assertionSignatureValidators;
    }

    public void validate(WebAuthnUserDetails userDetails, WebAuthnAuthenticator webAuthnAuthenticator, WebAuthnAssertionAuthenticationToken authenticationToken) {

        if (authenticationToken.getCredentials() == null) {
            logger.debug("Authentication failed: no credentials provided");

            throw new BadCredentialsException(messages.getMessage(
                    "WebAuthnAuthenticationContextValidator.badCredentials",
                    "Bad credentials"));
        }
        WebAuthnAuthenticationContext webAuthnAuthenticationContext = authenticationToken.getCredentials();
        AbstractCredentialPublicKey credentialPublicKey = webAuthnAuthenticator.getAttestationData().getCredentialPublicKey();
        String username = userDetails.getUsername();

        RelyingParty relyingParty = webAuthnAuthenticationContext.getRelyingParty();
        CollectedClientData collectedClientData = webAuthnAuthenticationContext.getCollectedClientData();
        WebAuthnAuthenticatorData authenticatorData = webAuthnAuthenticationContext.getAuthenticatorData();

        verifyUserVerified(webAuthnAuthenticationContext, username);

        // Verify that the challenge member of C matches the challenge that was sent to the authenticator
        // in the PublicKeyCredentialRequestOptions passed to the get() call.
        try{
            challengeValidator.validate(collectedClientData, relyingParty);
        }
        catch (com.webauthn4j.webauthn.exception.BadChallengeException e){
            throw new BadChallengeException(messages.getMessage("WebAuthnAuthenticationContextValidator.badChallenge", "Bad challenge"), e);
        }

        // Verify that the origin member of the collectedClientData matches the Relying Party's origin.
        try{
            originValidator.validate(collectedClientData, relyingParty);
        }
        catch (com.webauthn4j.webauthn.exception.BadOriginException e){
            throw new BadOriginException(messages.getMessage("WebAuthnAuthenticationContextValidator.badOrigin", "Bad origin"), e);
        }

        // Verify that the tokenBindingId member of the collectedClientData (if present) matches the Token Binding ID for
        // the TLS connection over which the signature was obtained.
        //TODO: not yet implemented

        // Verify that the clientExtensions member of the collectedClientData is a proper subset of the extensions
        // requested by the Relying Party and that the authenticatorExtensions in the collectedClientData is also
        // a proper subset of the extensions requested by the Relying Party.
        // TODO: not yet implemented

        // Verify that the RP ID hash in the authenticatorData is the SHA-256 hash of the RP ID
        // expected by the Relying Party.
        try{
            rpIdHashValidator.validate(authenticatorData.getRpIdHash(), relyingParty);
        }
        catch (com.webauthn4j.webauthn.exception.BadRpIdException e){
            throw new BadRpIdException(messages.getMessage("WebAuthnAuthenticationContextValidator.badRpId", "Bad rpId"), e);
        }

        // Using the credential public key, validate that sig is a valid signature over
        // the binary concatenation of the authenticatorData and the hash of the collectedClientData.
        try{
            verifyAssertionSignature(webAuthnAuthenticator, webAuthnAuthenticationContext, credentialPublicKey);
        }
        catch (com.webauthn4j.webauthn.exception.BadSignatureException e){
            throw new BadSignatureException(messages.getMessage("WebAuthnAuthenticationContextValidator.badSignature", "Bad signature"), e);
        }
    }

    void verifyAssertionSignature(WebAuthnAuthenticator webAuthnAuthenticator, WebAuthnAuthenticationContext webAuthnAuthenticationContext, AbstractCredentialPublicKey credentialPublicKey) {
        for (AssertionSignatureValidator assertionSignatureValidator : assertionSignatureValidators) {
            if (assertionSignatureValidator.supports(webAuthnAuthenticator.getFormat())) {
                assertionSignatureValidator.verifySignature(webAuthnAuthenticationContext, credentialPublicKey);
                return;
            }
        }

        logger.debug("Authentication failed: publicKey does not match stored value");
        throw new BadCredentialsException(messages.getMessage(
                "WebAuthnAuthenticationContextValidator.badCredentials",
                "Bad credentials"));
    }

    void verifyUserVerified(WebAuthnAuthenticationContext webAuthnAuthenticationContext, String username) {
        if (webAuthnAuthenticationContext.getAuthenticatorData().isFlagUV()) {
            return;
        }
        Authentication currentAuthentication = SecurityContextHolder.getContext().getAuthentication();
        if (isFirstOfMFAPassedUser(currentAuthentication, username)) {
            return;
        }
        throw new UserNotVerifiedException(messages.getMessage(
                "WebAuthnAuthenticationContextValidator.userNotVerified",
                "User not verified"));
    }

    boolean isFirstOfMFAPassedUser(Authentication authentication, String username) {
        return authentication instanceof FirstOfMultiFactorAuthenticationToken
                && username.equals(authentication.getName());
    }

}
