package com.webauthn4j.reactive.verifier;

import com.webauthn4j.verifier.AuthenticationObject;

import java.util.concurrent.CompletionStage;

public interface CustomAuthenticationReactiveVerifier {
    CompletionStage<Void> verify(AuthenticationObject authenticationObject);
}
