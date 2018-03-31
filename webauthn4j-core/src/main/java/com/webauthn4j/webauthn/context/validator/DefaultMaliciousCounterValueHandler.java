package com.webauthn4j.webauthn.context.validator;

import com.webauthn4j.webauthn.authenticator.WebAuthnAuthenticator;
import com.webauthn4j.webauthn.context.WebAuthnAuthenticationContext;
import com.webauthn4j.webauthn.exception.MaliciousCounterValueException;

public class DefaultMaliciousCounterValueHandler implements MaliciousCounterValueHandler {
    @Override
    public void maliciousCounterValueDetected(WebAuthnAuthenticationContext webAuthnAuthenticationContext, WebAuthnAuthenticator authenticator) {
        throw new MaliciousCounterValueException("Malicious counter value is detected. Cloned authenticators exist in parallel.");
    }
}
