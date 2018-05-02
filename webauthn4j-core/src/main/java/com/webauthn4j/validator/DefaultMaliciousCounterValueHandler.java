package com.webauthn4j.validator;

import com.webauthn4j.WebAuthnAuthenticationContext;
import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.validator.exception.MaliciousCounterValueException;

public class DefaultMaliciousCounterValueHandler implements MaliciousCounterValueHandler {
    @Override
    public void maliciousCounterValueDetected(WebAuthnAuthenticationContext webAuthnAuthenticationContext, Authenticator authenticator) {
        throw new MaliciousCounterValueException("Malicious counter value is detected. Cloned authenticators exist in parallel.");
    }
}
