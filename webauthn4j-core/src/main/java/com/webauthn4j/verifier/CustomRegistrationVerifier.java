package com.webauthn4j.verifier;

import org.jetbrains.annotations.NotNull;

public interface CustomRegistrationVerifier {

    void verify(@NotNull RegistrationObject registrationObject);

}
