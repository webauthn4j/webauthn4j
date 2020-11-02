package com.webauthn4j.validator;

import org.checkerframework.checker.nullness.qual.NonNull;

public interface CustomCoreRegistrationValidator {

    void validate(@NonNull CoreRegistrationObject registrationObject);

}
