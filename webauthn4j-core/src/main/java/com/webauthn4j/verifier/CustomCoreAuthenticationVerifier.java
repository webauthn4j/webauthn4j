package com.webauthn4j.verifier;

import org.jetbrains.annotations.NotNull;

public interface CustomCoreAuthenticationVerifier {

    void verify(@NotNull CoreAuthenticationObject authenticationObject);

}
