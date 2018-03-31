package com.webauthn4j.webauthn.context.validator;

import com.webauthn4j.webauthn.authenticator.WebAuthnAuthenticator;
import com.webauthn4j.webauthn.context.WebAuthnAuthenticationContext;

public interface MaliciousCounterValueHandler {

    void maliciousCounterValueDetected(WebAuthnAuthenticationContext webAuthnAuthenticationContext, WebAuthnAuthenticator authenticator);
}
