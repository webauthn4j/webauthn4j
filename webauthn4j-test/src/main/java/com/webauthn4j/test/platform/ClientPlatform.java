package com.webauthn4j.test.platform;

import com.webauthn4j.client.CollectedClientData;
import com.webauthn4j.client.Origin;
import com.webauthn4j.client.challenge.Challenge;
import com.webauthn4j.test.authenticator.fido.u2f.FIDOU2FAuthenticator;
import com.webauthn4j.test.authenticator.fido.u2f.FIDOU2FAuthenticatorAdaptor;
import com.webauthn4j.util.WIP;
import com.webauthn4j.validator.exception.ValidationException;

@WIP
public class ClientPlatform {

    private Origin origin;
    //TODO: support multiple authenticators
    private FIDOU2FAuthenticatorAdaptor fidoU2FAuthenticatorAdaptor;

    public ClientPlatform(Origin origin, FIDOU2FAuthenticatorAdaptor fidoU2FAuthenticatorAdaptor){
        this.origin = origin;
        this.fidoU2FAuthenticatorAdaptor = fidoU2FAuthenticatorAdaptor;
    }

    public ClientPlatform(FIDOU2FAuthenticatorAdaptor fidoU2FAuthenticatorAdaptor){
        this(new Origin("http://localhost:8080"), fidoU2FAuthenticatorAdaptor);
    }

    public ClientPlatform(Origin origin){
        this(origin, new FIDOU2FAuthenticatorAdaptor());
    }

    public ClientPlatform(){
        this(new Origin("http://localhost:8080"), new FIDOU2FAuthenticatorAdaptor());
    }

    public WebAuthnRegistrationRequest create(PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions,
                                              CollectedClientData collectedClientData,
                                              RegistrationEmulationOption registrationEmulationOption){
        return fidoU2FAuthenticatorAdaptor.register(publicKeyCredentialCreationOptions, collectedClientData, registrationEmulationOption);
    }

    public WebAuthnRegistrationRequest create(PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions,
                                              RegistrationEmulationOption registrationEmulationOption){
        CollectedClientData collectedClientData = createCollectedClientData(CollectedClientData.TYPE_WEBAUTHN_CREATE, publicKeyCredentialCreationOptions.getChallenge());

        return create(publicKeyCredentialCreationOptions, collectedClientData, registrationEmulationOption);
    }

    public WebAuthnRegistrationRequest create(PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions, CollectedClientData collectedClientData){
        return create(publicKeyCredentialCreationOptions, collectedClientData, new RegistrationEmulationOption());
    }

    public WebAuthnRegistrationRequest create(PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions){
        return create(publicKeyCredentialCreationOptions, new RegistrationEmulationOption());
    }

    public WebAuthnAuthenticationRequest get(PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions,
                                             CollectedClientData collectedClientData,
                                             AuthenticationEmulationOption authenticationEmulationOption){

        for(PublicKeyCredentialDescriptor credentialDescriptor : publicKeyCredentialRequestOptions.getAllowCredentials()){
            return fidoU2FAuthenticatorAdaptor.authenticate(publicKeyCredentialRequestOptions, collectedClientData, credentialDescriptor, authenticationEmulationOption);
        }
        throw new NoAuthenticatorSuccessException();
    }

    public WebAuthnAuthenticationRequest get(PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions, CollectedClientData collectedClientData){
        return get(publicKeyCredentialRequestOptions, collectedClientData, new AuthenticationEmulationOption());
    }

    public WebAuthnAuthenticationRequest get(PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions){
        CollectedClientData collectedClientData = createCollectedClientData(CollectedClientData.TYPE_WEBAUTHN_GET, publicKeyCredentialRequestOptions.getChallenge());
        return get(publicKeyCredentialRequestOptions, collectedClientData);
    }

    public CollectedClientData createCollectedClientData(String type, Challenge challenge) {
        return new CollectedClientData(type, challenge, origin, null);
    }

}
