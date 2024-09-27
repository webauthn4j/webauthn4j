package com.webauthn4j.async.verifier;

import com.webauthn4j.util.CompletionStageUtil;
import com.webauthn4j.verifier.AuthenticationObject;
import com.webauthn4j.verifier.OriginVerifier;
import com.webauthn4j.verifier.OriginVerifierImpl;
import com.webauthn4j.verifier.RegistrationObject;
import org.jetbrains.annotations.NotNull;

import java.util.concurrent.CompletionStage;

public class OriginAsyncVerifierImpl implements OriginAsyncVerifier{

    private final OriginVerifier originVerifier = new OriginVerifierImpl();

    @Override
    public CompletionStage<Void> verify(@NotNull RegistrationObject registrationObject) {
        return CompletionStageUtil.supply(()->{
            originVerifier.verify(registrationObject);
            return null;
        });
    }

    @Override
    public CompletionStage<Void> verify(@NotNull AuthenticationObject authenticationObject) {
        return CompletionStageUtil.supply(()->{
            originVerifier.verify(authenticationObject);
            return null;
        });
    }
}
