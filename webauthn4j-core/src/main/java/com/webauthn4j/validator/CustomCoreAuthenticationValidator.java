package com.webauthn4j.validator;

import org.jetbrains.annotations.NotNull;

public interface CustomCoreAuthenticationValidator {

    void validate(@NotNull CoreAuthenticationObject authenticationObject);

}
