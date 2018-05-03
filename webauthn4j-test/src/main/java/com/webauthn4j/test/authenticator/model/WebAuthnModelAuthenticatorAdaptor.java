package com.webauthn4j.test.authenticator.model;

import com.webauthn4j.client.CollectedClientData;
import com.webauthn4j.test.platform.*;

public class WebAuthnModelAuthenticatorAdaptor implements AuthenticatorAdaptor {

    private WebAuthnModelAuthenticator webAuthnModelAuthenticator = new WebAuthnModelAuthenticator();

    @Override
    public WebAuthnRegistrationRequest register(PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions, CollectedClientData collectedClientData) {
        return null;
    }

    @Override
    public WebAuthnRegistrationRequest register(PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions, CollectedClientData collectedClientData, RegistrationEmulationOption registrationEmulationOption) {
        return null;
    }

    @Override
    public WebAuthnAuthenticationRequest authenticate(PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions, CollectedClientData collectedClientData, PublicKeyCredentialDescriptor credentialDescriptor) {
        return null;
    }

    @Override
    public WebAuthnAuthenticationRequest authenticate(PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions, CollectedClientData collectedClientData, PublicKeyCredentialDescriptor credentialDescriptor, AuthenticationEmulationOption authenticationEmulationOption) {
        return null;
    }
}
