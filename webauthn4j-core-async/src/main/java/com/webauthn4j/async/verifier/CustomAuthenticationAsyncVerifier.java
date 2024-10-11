package com.webauthn4j.async.verifier;

import com.webauthn4j.verifier.AuthenticationObject;

import java.util.concurrent.CompletionStage;

/**
 * Handler interface to verify authentication with custom logic
 */
public interface CustomAuthenticationAsyncVerifier {
    CompletionStage<Void> verify(AuthenticationObject authenticationObject);
}
