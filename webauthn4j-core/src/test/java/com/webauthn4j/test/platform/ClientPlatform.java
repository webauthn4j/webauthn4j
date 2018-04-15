package com.webauthn4j.test.platform;

import com.webauthn4j.attestation.WebAuthnAttestationObject;
import com.webauthn4j.attestation.authenticator.WebAuthnAuthenticatorData;
import com.webauthn4j.client.CollectedClientData;
import com.webauthn4j.client.Origin;
import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.converter.WebAuthnAttestationObjectConverter;
import com.webauthn4j.converter.WebAuthnAuthenticatorDataConverter;
import com.webauthn4j.test.token.AuthenticateRequest;
import com.webauthn4j.test.token.AuthenticateResponse;
import com.webauthn4j.test.token.FIDOU2FSoftwareToken;
import com.webauthn4j.util.MessageDigestUtil;

import java.nio.charset.StandardCharsets;

public class ClientPlatform {

    private FIDOU2FSoftwareToken softwareToken = new FIDOU2FSoftwareToken();
    private Origin origin = new Origin("http://localhost:8080");

    private CollectedClientDataConverter collectedClientDataConverter = new CollectedClientDataConverter();
    private WebAuthnAttestationObjectConverter webAuthnAttestationObjectConverter = new WebAuthnAttestationObjectConverter();
    private WebAuthnAuthenticatorDataConverter webAuthnAuthenticatorDataConverter = new WebAuthnAuthenticatorDataConverter();

    public ClientPlatform(){

    }

    public WebAuthnRegistrationRequest create(PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions){
        CollectedClientData collectedClientData = new CollectedClientData();
        WebAuthnAttestationObject webAuthnAttestationObject = new WebAuthnAttestationObject();

        collectedClientData.setType("webauthn.create");
        collectedClientData.setChallenge(publicKeyCredentialCreationOptions.getChallenge());
        collectedClientData.setOrigin(origin);

        byte[] collectedClientDataBytes = collectedClientDataConverter.convertToBytes(collectedClientData);
        byte[] attestationObjectBytes = webAuthnAttestationObjectConverter.convertToBytes(webAuthnAttestationObject);
        return new WebAuthnRegistrationRequest(collectedClientDataBytes, attestationObjectBytes);
    }

    public WebAuthnAuthenticationRequest get(PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions){

        for(PublicKeyCredentialDescriptor credentialDescriptor : publicKeyCredentialRequestOptions.getAllowCredentials()){

            String rpId = publicKeyCredentialRequestOptions.getRpId();
            CollectedClientData collectedClientData = new CollectedClientData();
            byte[] collectedClientDataBytes = collectedClientDataConverter.convertToBytes(collectedClientData);

            byte control = 0x00;
            byte[] challenge = publicKeyCredentialRequestOptions.getChallenge().getValue();
            byte[] applicationParameter = MessageDigestUtil.createMessageDigest("SHA-256").digest(rpId.getBytes(StandardCharsets.UTF_8));
            byte[] keyHandle = credentialDescriptor.getId();

            AuthenticateRequest authenticateRequest = new AuthenticateRequest(control, challenge, applicationParameter, keyHandle);

            AuthenticateResponse authenticateResponse = softwareToken.authenticate(authenticateRequest);

            String credentialId = rpId;
            WebAuthnAuthenticatorData webAuthnAuthenticatorData = new WebAuthnAuthenticatorData();
            byte[] authenticatorDataBytes = webAuthnAuthenticatorDataConverter.convertToBytes(webAuthnAuthenticatorData);
            byte[] signature = authenticateResponse.getSignature();
            return new WebAuthnAuthenticationRequest(credentialId, collectedClientDataBytes, authenticatorDataBytes, signature);
        }
        throw new NoAuthenticatorSuccessException();
    }

}
