package com.webauthn4j.reactive.verifier;

import com.webauthn4j.verifier.RegistrationObject;

import java.util.concurrent.CompletionStage;

public interface CustomRegistrationReactiveVerifier {
    CompletionStage<Void> verify(RegistrationObject registrationObject);
}
