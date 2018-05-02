package com.webauthn4j.test.platform;

import com.webauthn4j.client.CollectedClientData;

public interface AuthenticatorAdaptor {

    WebAuthnRegistrationRequest register(PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions,
                                         CollectedClientData collectedClientData);

    WebAuthnRegistrationRequest register(PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions,
                                         CollectedClientData collectedClientData,
                                         RegistrationEmulationOption registrationEmulationOption);

    WebAuthnAuthenticationRequest authenticate(PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions,
                                               CollectedClientData collectedClientData,
                                               PublicKeyCredentialDescriptor credentialDescriptor);

    WebAuthnAuthenticationRequest authenticate(PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions,
                                               CollectedClientData collectedClientData,
                                               PublicKeyCredentialDescriptor credentialDescriptor,
                                               AuthenticationEmulationOption authenticationEmulationOption);

}
