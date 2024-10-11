package com.webauthn4j.verifier;

import org.jetbrains.annotations.NotNull;

/**
 * Handler interface to verify registration with custom logic
 */
public interface CustomCoreRegistrationVerifier {

    void verify(@NotNull CoreRegistrationObject registrationObject);

}
