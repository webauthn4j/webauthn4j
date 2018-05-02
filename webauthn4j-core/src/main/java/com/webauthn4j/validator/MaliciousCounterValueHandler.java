package com.webauthn4j.validator;

import com.webauthn4j.WebAuthnAuthenticationContext;
import com.webauthn4j.authenticator.Authenticator;

public interface MaliciousCounterValueHandler {

    void maliciousCounterValueDetected(WebAuthnAuthenticationContext webAuthnAuthenticationContext, Authenticator authenticator);
}
