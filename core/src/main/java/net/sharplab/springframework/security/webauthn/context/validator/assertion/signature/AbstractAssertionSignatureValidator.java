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
