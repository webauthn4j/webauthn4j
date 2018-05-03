package com.webauthn4j.test.platform;

import com.webauthn4j.client.CollectedClientData;
import com.webauthn4j.client.Origin;
import com.webauthn4j.client.challenge.Challenge;
import com.webauthn4j.test.authenticator.fido.u2f.FIDOU2FAuthenticatorAdaptor;
import com.webauthn4j.util.WIP;
import com.webauthn4j.validator.exception.ValidationException;

import java.util.Arrays;
import java.util.List;

@WIP
public class ClientPlatform {

    private Origin origin;
    //TODO: support multiple authenticators
    private AuthenticatorAdaptor authenticatorAdaptor;

    public ClientPlatform(Origin origin, AuthenticatorAdaptor authenticatorAdaptor){
        this.origin = origin;
        this.authenticatorAdaptor = authenticatorAdaptor;
    }

    public ClientPlatform(AuthenticatorAdaptor authenticatorAdaptor){
        this(new Origin("http://localhost:8080"), authenticatorAdaptor);
    }

    public ClientPlatform(Origin origin){
        this(origin, new FIDOU2FAuthenticatorAdaptor());
    }

    public ClientPlatform(){
        this(new Origin("http://localhost:8080"));
    }

    public WebAuthnRegistrationRequest create(PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions,
                                              RegistrationEmulationOption registrationEmulationOption){
        CollectedClientData collectedClientData;
        if(registrationEmulationOption.isCollectedClientDataOverrideEnabled()){
            collectedClientData = registrationEmulationOption.getCollectedClientData();
        }
        else {
            collectedClientData = createCollectedClientData(CollectedClientData.TYPE_WEBAUTHN_CREATE, publicKeyCredentialCreationOptions.getChallenge());
        }

        if(authenticatorAdaptor == null){
            throw new NoAuthenticatorSuccessException();
        }
        return authenticatorAdaptor.register(publicKeyCredentialCreationOptions, collectedClientData, registrationEmulationOption);
    }

    public WebAuthnRegistrationRequest create(PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions){
        return create(publicKeyCredentialCreationOptions, new RegistrationEmulationOption());
    }

    public WebAuthnAuthenticationRequest get(PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions,
                                             CollectedClientData collectedClientData,
                                             AuthenticationEmulationOption authenticationEmulationOption){

        NoAuthenticatorSuccessException noAuthenticatorSuccessException = new NoAuthenticatorSuccessException();
        if(authenticatorAdaptor == null){
            throw  noAuthenticatorSuccessException;
        }
        for(PublicKeyCredentialDescriptor credentialDescriptor : publicKeyCredentialRequestOptions.getAllowCredentials()){
            try{
                return authenticatorAdaptor.authenticate(publicKeyCredentialRequestOptions, collectedClientData, credentialDescriptor, authenticationEmulationOption);
            }
            catch (ValidationException e){
                noAuthenticatorSuccessException.addSuppressed(e);
            }
        }
        throw noAuthenticatorSuccessException;
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
