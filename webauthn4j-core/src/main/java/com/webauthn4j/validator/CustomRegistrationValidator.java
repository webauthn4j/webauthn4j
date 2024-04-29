package com.webauthn4j.validator;

import org.jetbrains.annotations.NotNull;

public interface CustomRegistrationValidator {

    void validate(@NotNull RegistrationObject registrationObject);

}
