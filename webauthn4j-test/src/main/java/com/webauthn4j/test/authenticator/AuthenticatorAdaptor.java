package com.webauthn4j.test.authenticator;

import com.webauthn4j.client.CollectedClientData;
import com.webauthn4j.test.client.AuthenticationEmulationOption;
import com.webauthn4j.test.client.PublicKeyCredentialCreationOptions;
import com.webauthn4j.test.client.PublicKeyCredentialRequestOptions;
import com.webauthn4j.test.client.RegistrationEmulationOption;

public interface AuthenticatorAdaptor {

    CredentialCreationResponse register(PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions,
                                        CollectedClientData collectedClientData);

    CredentialCreationResponse register(PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions,
                                        CollectedClientData collectedClientData,
                                        RegistrationEmulationOption registrationEmulationOption);

    CredentialRequestResponse authenticate(PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions,
                                           CollectedClientData collectedClientData);

    CredentialRequestResponse authenticate(PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions,
                                           CollectedClientData collectedClientData,
                                           AuthenticationEmulationOption authenticationEmulationOption);

}
