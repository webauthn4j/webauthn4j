package com.webauthn4j.validator;

import com.webauthn4j.authenticator.WebAuthnAuthenticator;
import com.webauthn4j.WebAuthnAuthenticationContext;
import com.webauthn4j.validator.exception.MaliciousCounterValueException;

public class DefaultMaliciousCounterValueHandler implements MaliciousCounterValueHandler {
    @Override
    public void maliciousCounterValueDetected(WebAuthnAuthenticationContext webAuthnAuthenticationContext, WebAuthnAuthenticator authenticator) {
        throw new MaliciousCounterValueException("Malicious counter value is detected. Cloned authenticators exist in parallel.");
    }
}
