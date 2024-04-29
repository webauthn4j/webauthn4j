package com.webauthn4j.validator;

import org.jetbrains.annotations.NotNull;

public interface CustomAuthenticationValidator {

    void validate(@NotNull AuthenticationObject authenticationObject);

}
