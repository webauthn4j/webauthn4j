package com.webauthn4j.test.platform;

import com.webauthn4j.attestation.AttestationObject;
import com.webauthn4j.attestation.statement.AttestationStatement;
import com.webauthn4j.attestation.statement.NoneAttestationStatement;
import com.webauthn4j.client.CollectedClientData;
import com.webauthn4j.client.Origin;
import com.webauthn4j.client.challenge.Challenge;
import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.test.authenticator.CredentialRequestResponse;
import com.webauthn4j.test.authenticator.AuthenticatorAdaptor;
import com.webauthn4j.test.authenticator.CredentialCreationResponse;
import com.webauthn4j.test.authenticator.fido.u2f.FIDOU2FAuthenticatorAdaptor;
import com.webauthn4j.util.WIP;
import com.webauthn4j.util.exception.NotImplementedException;
import com.webauthn4j.validator.exception.ValidationException;

import java.util.List;

@WIP
public class ClientPlatform {

    private AttestationObjectConverter attestationObjectConverter = new AttestationObjectConverter();
    private CollectedClientDataConverter collectedClientDataConverter = new CollectedClientDataConverter();

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

    public PublicKeyCredential<AuthenticatorAttestationResponse> create(PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions,
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
        CredentialCreationResponse credentialCreationResponse =
                authenticatorAdaptor.register(publicKeyCredentialCreationOptions, collectedClientData, registrationEmulationOption);

        AttestationObject attestationObject = credentialCreationResponse.getAttestationObject();
        AttestationStatement attestationStatement = credentialCreationResponse.getAttestationObject().getAttestationStatement();
        switch (publicKeyCredentialCreationOptions.getAttestation()) {
            case DIRECT:
                // nop
                break;
            case INDIRECT:
                throw new NotImplementedException();
            case NONE:
                attestationStatement = new NoneAttestationStatement();
                break;
            default:
                throw new NotImplementedException();
        }
        attestationObject = new AttestationObject(attestationObject.getAuthenticatorData(), attestationStatement);
        byte[] attestationObjectBytes = attestationObjectConverter.convertToBytes(attestationObject);

        byte[] credentialId = credentialCreationResponse.getAttestationObject().getAuthenticatorData().getAttestedCredentialData().getCredentialId();
        byte[] collectedClientDataBytes = collectedClientDataConverter.convertToBytes(collectedClientData);
        return new PublicKeyCredential<>(
                credentialId,
                new AuthenticatorAttestationResponse(collectedClientDataBytes, attestationObjectBytes)
        );
    }

    public PublicKeyCredential<AuthenticatorAttestationResponse> create(PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions){
        return create(publicKeyCredentialCreationOptions, new RegistrationEmulationOption());
    }

    public PublicKeyCredential<AuthenticatorAssertionResponse> get(PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions,
                                              CollectedClientData collectedClientData,
                                              AuthenticationEmulationOption authenticationEmulationOption){

        NoAuthenticatorSuccessException noAuthenticatorSuccessException = new NoAuthenticatorSuccessException();
        if(authenticatorAdaptor == null){
            throw  noAuthenticatorSuccessException;
        }
        try{
            CredentialRequestResponse credentialRequestResponse =
                    authenticatorAdaptor.authenticate(publicKeyCredentialRequestOptions, collectedClientData, authenticationEmulationOption);

            byte[] credentialId = credentialRequestResponse.getCredentialId();
            return new PublicKeyCredential<>(credentialId, new AuthenticatorAssertionResponse(
                    credentialRequestResponse.getCollectedClientDataBytes(),
                    credentialRequestResponse.getAuthenticatorDataBytes(),
                    credentialRequestResponse.getSignature(),
                    credentialRequestResponse.getUserHandle()
            ));
        }
        catch (ValidationException e){
            noAuthenticatorSuccessException.addSuppressed(e);
        }
        throw noAuthenticatorSuccessException;
    }

    public PublicKeyCredential<AuthenticatorAssertionResponse> get(PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions, CollectedClientData collectedClientData){
        return get(publicKeyCredentialRequestOptions, collectedClientData, new AuthenticationEmulationOption());
    }

    public PublicKeyCredential<AuthenticatorAssertionResponse> get(PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions){
        CollectedClientData collectedClientData = createCollectedClientData(CollectedClientData.TYPE_WEBAUTHN_GET, publicKeyCredentialRequestOptions.getChallenge());
        return get(publicKeyCredentialRequestOptions, collectedClientData);
    }

    public CollectedClientData createCollectedClientData(String type, Challenge challenge) {
        return new CollectedClientData(type, challenge, origin, null);
    }

}
