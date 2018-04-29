package com.webauthn4j.validator;

import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.WebAuthnAuthenticationContext;

public interface MaliciousCounterValueHandler {

    void maliciousCounterValueDetected(WebAuthnAuthenticationContext webAuthnAuthenticationContext, Authenticator authenticator);
}
