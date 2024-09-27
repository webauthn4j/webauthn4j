package com.webauthn4j.async.verifier;

import com.webauthn4j.verifier.AuthenticationObject;
import com.webauthn4j.verifier.RegistrationObject;
import org.jetbrains.annotations.NotNull;

import java.util.concurrent.CompletionStage;

public interface OriginAsyncVerifier {

    CompletionStage<Void> verify(@NotNull RegistrationObject registrationObject);

    CompletionStage<Void> verify(@NotNull AuthenticationObject authenticationObject);

}
