package com.webauthn4j.validator;

import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientOutput;

public interface CustomAuthenticationValidator {

    void validate(AuthenticationObject<AuthenticationExtensionAuthenticatorOutput, AuthenticationExtensionClientOutput> authenticationObject);

}
