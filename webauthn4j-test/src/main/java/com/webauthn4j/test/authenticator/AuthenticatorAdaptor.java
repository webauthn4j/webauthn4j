package com.webauthn4j.test.authenticator;

import com.webauthn4j.client.CollectedClientData;
import com.webauthn4j.test.platform.AuthenticationEmulationOption;
import com.webauthn4j.test.platform.PublicKeyCredentialCreationOptions;
import com.webauthn4j.test.platform.PublicKeyCredentialRequestOptions;
import com.webauthn4j.test.platform.RegistrationEmulationOption;

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
