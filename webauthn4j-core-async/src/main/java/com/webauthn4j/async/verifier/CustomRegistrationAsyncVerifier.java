package com.webauthn4j.async.verifier;

import com.webauthn4j.verifier.RegistrationObject;

import java.util.concurrent.CompletionStage;

/**
 * Handler interface to verify registration with custom logic
 */
public interface CustomRegistrationAsyncVerifier {
    CompletionStage<Void> verify(RegistrationObject registrationObject);
}
