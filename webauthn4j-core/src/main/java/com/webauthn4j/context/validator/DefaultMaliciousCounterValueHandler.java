package com.webauthn4j.context.validator;

import com.webauthn4j.authenticator.WebAuthnAuthenticator;
import com.webauthn4j.context.WebAuthnAuthenticationContext;
import com.webauthn4j.context.validator.exception.MaliciousCounterValueException;

public class DefaultMaliciousCounterValueHandler implements MaliciousCounterValueHandler {
    @Override
    public void maliciousCounterValueDetected(WebAuthnAuthenticationContext webAuthnAuthenticationContext, WebAuthnAuthenticator authenticator) {
        throw new MaliciousCounterValueException("Malicious counter value is detected. Cloned authenticators exist in parallel.");
    }
}
