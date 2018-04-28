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

        return fidoU2FAuthenticatorAdaptor.register(publicKeyCredentialCreationOptions, collectedClientData);
    }

    public WebAuthnAuthenticationRequest get(PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions){

        CollectedClientData collectedClientData = createCollectedClientData(CollectedClientData.TYPE_WEBAUTHN_GET, publicKeyCredentialRequestOptions.getChallenge());
        for(PublicKeyCredentialDescriptor credentialDescriptor : publicKeyCredentialRequestOptions.getAllowCredentials()){
            return fidoU2FAuthenticatorAdaptor.authenticate(publicKeyCredentialRequestOptions, collectedClientData, credentialDescriptor);
        }
        throw new NoAuthenticatorSuccessException();
    }

    private CollectedClientData createCollectedClientData(String type, Challenge challenge) {
        CollectedClientData collectedClientData = new CollectedClientData();
        collectedClientData.setType(type);
        collectedClientData.setChallenge(challenge);
        collectedClientData.setOrigin(origin);
        collectedClientData.setHashAlgorithm("SHA-256");
        collectedClientData.setTokenBinding(null);
        collectedClientData.setClientExtensions(null);
        collectedClientData.setAuthenticatorExtensions(null);
        return collectedClientData;
    }

}
