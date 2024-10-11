package com.webauthn4j.verifier;

import org.jetbrains.annotations.NotNull;

/**
 * Handler interface to verify registration with custom logic
 */
public interface CustomRegistrationVerifier {

    void verify(@NotNull RegistrationObject registrationObject);

}
