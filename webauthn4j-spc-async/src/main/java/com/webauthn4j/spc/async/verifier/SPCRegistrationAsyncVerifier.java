package com.webauthn4j.spc.async.verifier;

import com.webauthn4j.async.verifier.CustomRegistrationAsyncVerifier;
import com.webauthn4j.spc.verifier.SPCRegistrationVerifier;
import com.webauthn4j.util.CompletionStageUtil;
import com.webauthn4j.verifier.RegistrationObject;
import org.jetbrains.annotations.NotNull;

import java.util.concurrent.CompletionStage;

public class SPCRegistrationAsyncVerifier implements CustomRegistrationAsyncVerifier {

    private final SPCRegistrationVerifier syncVerifier = new SPCRegistrationVerifier();

    @Override
    public CompletionStage<Void> verify(@NotNull RegistrationObject registrationObject) {
        return CompletionStageUtil.supply(() -> {
            syncVerifier.verify(registrationObject);
            return null;
        });
    }
}
