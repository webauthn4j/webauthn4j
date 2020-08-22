package com.webauthn4j.validator;

public interface CustomCoreAuthenticationValidator {

    void validate(CoreAuthenticationObject authenticationObject);

}
