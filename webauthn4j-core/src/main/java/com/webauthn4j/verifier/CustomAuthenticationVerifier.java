package com.webauthn4j.verifier;

import org.jetbrains.annotations.NotNull;

public interface CustomAuthenticationVerifier {

    void verify(@NotNull AuthenticationObject authenticationObject);

}
