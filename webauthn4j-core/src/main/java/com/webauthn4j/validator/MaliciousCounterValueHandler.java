package com.webauthn4j.validator;

import com.webauthn4j.authenticator.WebAuthnAuthenticator;
import com.webauthn4j.WebAuthnAuthenticationContext;

public interface MaliciousCounterValueHandler {

    void maliciousCounterValueDetected(WebAuthnAuthenticationContext webAuthnAuthenticationContext, WebAuthnAuthenticator authenticator);
}
