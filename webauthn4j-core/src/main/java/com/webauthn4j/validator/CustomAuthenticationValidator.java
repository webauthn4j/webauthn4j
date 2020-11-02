package com.webauthn4j.validator;

import org.checkerframework.checker.nullness.qual.NonNull;

public interface CustomAuthenticationValidator {

    void validate(@NonNull AuthenticationObject authenticationObject);

}
