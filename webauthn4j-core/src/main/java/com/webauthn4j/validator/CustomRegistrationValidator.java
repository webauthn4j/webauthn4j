package com.webauthn4j.validator;

import org.checkerframework.checker.nullness.qual.NonNull;

public interface CustomRegistrationValidator {

    void validate(@NonNull RegistrationObject registrationObject);

}
