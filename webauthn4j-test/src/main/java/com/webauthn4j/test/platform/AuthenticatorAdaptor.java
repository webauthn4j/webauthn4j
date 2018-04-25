package com.webauthn4j.test.platform;

import com.webauthn4j.client.CollectedClientData;

public interface AuthenticatorAdaptor {

    WebAuthnRegistrationRequest register(PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions,
                                         CollectedClientData collectedClientData);

    WebAuthnAuthenticationRequest authenticate(PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions,
                                               CollectedClientData collectedClientData,
                                               PublicKeyCredentialDescriptor credentialDescriptor);
}
