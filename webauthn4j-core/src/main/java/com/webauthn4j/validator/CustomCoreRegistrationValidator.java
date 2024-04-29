package com.webauthn4j.validator;

import org.jetbrains.annotations.NotNull;

public interface CustomCoreRegistrationValidator {

    void validate(@NotNull CoreRegistrationObject registrationObject);

}
