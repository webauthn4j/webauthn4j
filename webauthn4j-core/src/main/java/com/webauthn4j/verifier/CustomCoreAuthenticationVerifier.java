package com.webauthn4j.verifier;

import org.jetbrains.annotations.NotNull;

/**
 * Handler interface to verify authentication with custom logic
 */
public interface CustomCoreAuthenticationVerifier {

    void verify(@NotNull CoreAuthenticationObject authenticationObject);

}
