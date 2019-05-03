package com.webauthn4j.validator;

public interface CustomAuthenticationValidator {

    void validate(AuthenticationObject authenticationObject);

}
