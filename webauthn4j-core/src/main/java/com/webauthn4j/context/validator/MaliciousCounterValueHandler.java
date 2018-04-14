package com.webauthn4j.context.validator;

import com.webauthn4j.authenticator.WebAuthnAuthenticator;
import com.webauthn4j.context.WebAuthnAuthenticationContext;

public interface MaliciousCounterValueHandler {

    void maliciousCounterValueDetected(WebAuthnAuthenticationContext webAuthnAuthenticationContext, WebAuthnAuthenticator authenticator);
}
