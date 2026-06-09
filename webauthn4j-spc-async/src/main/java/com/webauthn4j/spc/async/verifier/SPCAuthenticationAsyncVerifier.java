package com.webauthn4j.spc.async.verifier;

import com.webauthn4j.async.verifier.CustomAuthenticationAsyncVerifier;
import com.webauthn4j.spc.verifier.SPCAuthenticationVerifier;
import com.webauthn4j.util.CompletionStageUtil;
import com.webauthn4j.verifier.AuthenticationObject;
import org.jetbrains.annotations.NotNull;

import java.util.concurrent.CompletionStage;

public class SPCAuthenticationAsyncVerifier implements CustomAuthenticationAsyncVerifier {

    private final SPCAuthenticationVerifier syncVerifier = new SPCAuthenticationVerifier();

    @Override
    public CompletionStage<Void> verify(@NotNull AuthenticationObject authenticationObject) {
        return CompletionStageUtil.supply(() -> {
            syncVerifier.verify(authenticationObject);
            return null;
        });
    }
}
