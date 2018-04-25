package com.webauthn4j.test.authenticator.fido.u2f;

import com.webauthn4j.attestation.WebAuthnAttestationObject;
import com.webauthn4j.attestation.authenticator.Curve;
import com.webauthn4j.attestation.authenticator.ESCredentialPublicKey;
import com.webauthn4j.attestation.authenticator.WebAuthnAttestedCredentialData;
import com.webauthn4j.attestation.authenticator.WebAuthnAuthenticatorData;
import com.webauthn4j.attestation.statement.FIDOU2FAttestationStatement;
import com.webauthn4j.attestation.statement.NoneAttestationStatement;
import com.webauthn4j.attestation.statement.WebAuthnAttestationStatement;
import com.webauthn4j.client.CollectedClientData;
import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.converter.WebAuthnAttestationObjectConverter;
import com.webauthn4j.converter.WebAuthnAuthenticatorDataConverter;
import com.webauthn4j.exception.NotImplementedException;
import com.webauthn4j.test.platform.*;
import com.webauthn4j.util.CertificateUtil;
import com.webauthn4j.util.MessageDigestUtil;
import org.springframework.util.Base64Utils;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;

import static com.webauthn4j.attestation.authenticator.WebAuthnAuthenticatorData.*;

public class FIDOU2FAuthenticatorAdaptor implements AuthenticatorAdaptor{

    private FIDOU2FAuthenticator fidoU2FAuthenticator = new FIDOU2FAuthenticator();
    private CollectedClientDataConverter collectedClientDataConverter = new CollectedClientDataConverter();
    private WebAuthnAttestationObjectConverter webAuthnAttestationObjectConverter = new WebAuthnAttestationObjectConverter();
    private WebAuthnAuthenticatorDataConverter webAuthnAuthenticatorDataConverter = new WebAuthnAuthenticatorDataConverter();


    public WebAuthnRegistrationRequest register(PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions, CollectedClientData collectedClientData){
        String rpId = publicKeyCredentialCreationOptions.getRp().getId();
        byte[] rpIdHash = MessageDigestUtil.createMessageDigest("SHA-256").digest(rpId.getBytes(StandardCharsets.UTF_8));

        byte[] challengeParameter = MessageDigestUtil.createMessageDigest("SHA-256").digest(collectedClientDataConverter.convertToBytes(collectedClientData));
        byte[] applicationParameter = rpIdHash;
        RegistrationRequest registrationRequest = new RegistrationRequest(challengeParameter, applicationParameter);
        RegistrationResponse registrationResponse = fidoU2FAuthenticator.register(registrationRequest);

        WebAuthnAttestationStatement webAuthnAttestationStatement;
        switch (publicKeyCredentialCreationOptions.getAttestation()){
            case DIRECT:
                FIDOU2FAttestationStatement fidoU2FAttestationStatement = new FIDOU2FAttestationStatement();
                fidoU2FAttestationStatement.setSig(registrationResponse.getSignature());
                fidoU2FAttestationStatement.setX5c(CertificateUtil.generateCertPath(Collections.singletonList(registrationResponse.getAttestationCertificate())));
                webAuthnAttestationStatement = fidoU2FAttestationStatement;
                break;
            case INDIRECT:
                throw new NotImplementedException();
            case NONE:
                webAuthnAttestationStatement = new NoneAttestationStatement();
                break;
            default:
                throw new NotImplementedException();
        }


        ESCredentialPublicKey esCredentialPublicKey = convertToEsCredentialPublicKey(registrationResponse.getUserPublicKey());

        WebAuthnAttestedCredentialData webAuthnAttestedCredentialData = new WebAuthnAttestedCredentialData();
        webAuthnAttestedCredentialData.setAaGuid(new byte[16]); // zero-filled 16bytes(128bits) array
        webAuthnAttestedCredentialData.setCredentialId(registrationResponse.getKeyHandle());
        webAuthnAttestedCredentialData.setCredentialPublicKey(esCredentialPublicKey);

        byte flag = BIT_AT | BIT_UP;
        WebAuthnAuthenticatorData webAuthnAuthenticatorData = new WebAuthnAuthenticatorData();
        webAuthnAuthenticatorData.setRpIdHash(rpIdHash);
        webAuthnAuthenticatorData.setFlags(flag);
        webAuthnAuthenticatorData.setCounter(0);
        webAuthnAuthenticatorData.setAttestationData(webAuthnAttestedCredentialData);
        webAuthnAuthenticatorData.setExtensions(null);

        WebAuthnAttestationObject webAuthnAttestationObject = new WebAuthnAttestationObject();
        webAuthnAttestationObject.setAttestationStatement(webAuthnAttestationStatement);
        webAuthnAttestationObject.setAuthenticatorData(webAuthnAuthenticatorData);

        byte[] collectedClientDataBytes = collectedClientDataConverter.convertToBytes(collectedClientData);
        byte[] attestationObjectBytes = webAuthnAttestationObjectConverter.convertToBytes(webAuthnAttestationObject);
        return new WebAuthnRegistrationRequest(collectedClientDataBytes, attestationObjectBytes);
    }

    public WebAuthnAuthenticationRequest authenticate(PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions,
                                                      CollectedClientData collectedClientData,
                                                      PublicKeyCredentialDescriptor credentialDescriptor){
        byte[] collectedClientDataBytes = collectedClientDataConverter.convertToBytes(collectedClientData);
        String rpId = publicKeyCredentialRequestOptions.getRpId();

        byte control = 0x00;
        byte[] challenge = publicKeyCredentialRequestOptions.getChallenge().getValue();
        byte[] applicationParameter = MessageDigestUtil.createMessageDigest("SHA-256").digest(rpId.getBytes(StandardCharsets.UTF_8));
        byte[] keyHandle = credentialDescriptor.getId();

        AuthenticationRequest authenticationRequest = new AuthenticationRequest(control, challenge, applicationParameter, keyHandle);

        AuthenticationResponse authenticationResponse = fidoU2FAuthenticator.authenticate(authenticationRequest);

        String credentialId = rpId;
        WebAuthnAuthenticatorData webAuthnAuthenticatorData = new WebAuthnAuthenticatorData();
        byte[] authenticatorDataBytes = webAuthnAuthenticatorDataConverter.convertToBytes(webAuthnAuthenticatorData);
        byte[] signature = authenticationResponse.getSignature();
        return new WebAuthnAuthenticationRequest(credentialId, collectedClientDataBytes, authenticatorDataBytes, signature);
    }

    private ESCredentialPublicKey convertToEsCredentialPublicKey(byte[] publicKey) {
        byte[] x = Arrays.copyOfRange(publicKey, 1, 1 + 32);
        byte[] y = Arrays.copyOfRange(publicKey, 1 + 32, 1 + 32 + 32);
        ESCredentialPublicKey esCredentialPublicKey = new ESCredentialPublicKey();
        esCredentialPublicKey.setCurve(Curve.SECP256R1);
        esCredentialPublicKey.setX(x);
        esCredentialPublicKey.setY(y);
        return esCredentialPublicKey;
    }

}
