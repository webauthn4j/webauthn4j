package com.webauthn4j.test.platform;

import com.webauthn4j.client.CollectedClientData;
import com.webauthn4j.client.Origin;
import com.webauthn4j.client.challenge.Challenge;
import com.webauthn4j.test.authenticator.fido.u2f.FIDOU2FAuthenticatorAdaptor;
import com.webauthn4j.util.WIP;

@WIP
public class ClientPlatform {

    private Origin origin;
    //TODO: support multiple authenticators
    private FIDOU2FAuthenticatorAdaptor fidoU2FAuthenticatorAdaptor = new FIDOU2FAuthenticatorAdaptor();

    public ClientPlatform(Origin origin){
        this.origin = origin;
    }

    public ClientPlatform(){
        this(new Origin("http://localhost:8080"));
    }

    public WebAuthnRegistrationRequest create(PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions){
        CollectedClientData collectedClientData = createCollectedClientData(CollectedClientData.TYPE_WEBAUTHN_CREATE, publicKeyCredentialCreationOptions.getChallenge());

        return create(publicKeyCredentialCreationOptions, collectedClientData);
    }

    public WebAuthnRegistrationRequest create(PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions, CollectedClientData collectedClientData){
        return fidoU2FAuthenticatorAdaptor.register(publicKeyCredentialCreationOptions, collectedClientData);
    }

    public WebAuthnAuthenticationRequest get(PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions){

        CollectedClientData collectedClientData = createCollectedClientData(CollectedClientData.TYPE_WEBAUTHN_GET, publicKeyCredentialRequestOptions.getChallenge());
        for(PublicKeyCredentialDescriptor credentialDescriptor : publicKeyCredentialRequestOptions.getAllowCredentials()){
            return fidoU2FAuthenticatorAdaptor.authenticate(publicKeyCredentialRequestOptions, collectedClientData, credentialDescriptor);
        }
        throw new NoAuthenticatorSuccessException();
    }

    public CollectedClientData createCollectedClientData(String type, Challenge challenge) {
        return new CollectedClientData(type, challenge, origin, null);
    }

}
