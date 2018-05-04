package com.webauthn4j.test.authenticator;

import com.webauthn4j.client.CollectedClientData;
import com.webauthn4j.test.platform.*;

public interface AuthenticatorAdaptor {

    CredentialCreationResponse register(PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions,
                                        CollectedClientData collectedClientData);

    CredentialCreationResponse register(PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions,
                                        CollectedClientData collectedClientData,
                                        RegistrationEmulationOption registrationEmulationOption);

    CredentialRequestResponse authenticate(PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions,
                                           CollectedClientData collectedClientData,
                                           PublicKeyCredentialDescriptor credentialDescriptor);

    CredentialRequestResponse authenticate(PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions,
                                           CollectedClientData collectedClientData,
                                           PublicKeyCredentialDescriptor credentialDescriptor,
                                           AuthenticationEmulationOption authenticationEmulationOption);

}
