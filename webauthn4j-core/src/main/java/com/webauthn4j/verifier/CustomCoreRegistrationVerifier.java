package com.webauthn4j.verifier;

import org.jetbrains.annotations.NotNull;

public interface CustomCoreRegistrationVerifier {

    void verify(@NotNull CoreRegistrationObject registrationObject);

}
