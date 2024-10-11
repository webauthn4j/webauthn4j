package com.webauthn4j.async.verifier;

import com.webauthn4j.data.client.Origin;
import com.webauthn4j.verifier.AuthenticationObject;
import com.webauthn4j.verifier.RegistrationObject;
import org.jetbrains.annotations.NotNull;

import java.util.concurrent.CompletionStage;

/**
 * Handler interface to verify the given {@link Origin} instance
 */
public interface OriginAsyncVerifier {

    CompletionStage<Void> verify(@NotNull RegistrationObject registrationObject);

    CompletionStage<Void> verify(@NotNull AuthenticationObject authenticationObject);

}
