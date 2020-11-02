package com.webauthn4j.validator;

import org.checkerframework.checker.nullness.qual.NonNull;

public interface CustomCoreAuthenticationValidator {

    void validate(@NonNull CoreAuthenticationObject authenticationObject);

}
