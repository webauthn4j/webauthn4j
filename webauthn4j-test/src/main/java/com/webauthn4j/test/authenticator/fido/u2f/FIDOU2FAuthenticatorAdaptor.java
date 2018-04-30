package com.webauthn4j.test.authenticator.fido.u2f;

import com.webauthn4j.attestation.AttestationObject;
import com.webauthn4j.attestation.authenticator.*;
import com.webauthn4j.attestation.statement.FIDOU2FAttestationStatement;
import com.webauthn4j.attestation.statement.NoneAttestationStatement;
import com.webauthn4j.attestation.statement.AttestationStatement;
import com.webauthn4j.client.CollectedClientData;
import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.AuthenticatorDataConverter;
import com.webauthn4j.util.exception.NotImplementedException;
import com.webauthn4j.test.platform.*;
import com.webauthn4j.util.CertificateUtil;
import com.webauthn4j.util.MessageDigestUtil;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;

import static com.webauthn4j.attestation.authenticator.AuthenticatorData.BIT_AT;
import static com.webauthn4j.attestation.authenticator.AuthenticatorData.BIT_UP;

public class FIDOU2FAuthenticatorAdaptor implements AuthenticatorAdaptor{

    private FIDOU2FAuthenticator fidoU2FAuthenticator = new FIDOU2FAuthenticator();
    private CollectedClientDataConverter collectedClientDataConverter = new CollectedClientDataConverter();
    private AttestationObjectConverter attestationObjectConverter = new AttestationObjectConverter();
    private AuthenticatorDataConverter authenticatorDataConverter = new AuthenticatorDataConverter();


    public WebAuthnRegistrationRequest register(PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions, CollectedClientData collectedClientData){
        String rpId = publicKeyCredentialCreationOptions.getRp().getId();
        byte[] rpIdHash = MessageDigestUtil.createSHA256().digest(rpId.getBytes(StandardCharsets.UTF_8));

        byte[] challengeParameter = MessageDigestUtil.createSHA256().digest(collectedClientDataConverter.convertToBytes(collectedClientData));
        byte[] applicationParameter = rpIdHash;
        RegistrationRequest registrationRequest = new RegistrationRequest(challengeParameter, applicationParameter);
        RegistrationResponse registrationResponse = fidoU2FAuthenticator.register(registrationRequest);

        AttestationStatement attestationStatement;
        switch (publicKeyCredentialCreationOptions.getAttestation()){
            case DIRECT:
                attestationStatement = new FIDOU2FAttestationStatement(
                        CertificateUtil.generateCertPath(Collections.singletonList(registrationResponse.getAttestationCertificate())),
                        registrationResponse.getSignature()
                );
                break;
            case INDIRECT:
                throw new NotImplementedException();
            case NONE:
                attestationStatement = new NoneAttestationStatement();
                break;
            default:
                throw new NotImplementedException();
        }


        ESCredentialPublicKey esCredentialPublicKey = convertToEsCredentialPublicKey(registrationResponse.getUserPublicKey());

        byte[] aaGuid = new byte[16]; // zero-filled 16bytes(128bits) array
        AttestedCredentialData attestedCredentialData =
                new AttestedCredentialData(aaGuid, registrationResponse.getKeyHandle(), esCredentialPublicKey);

        byte flag = BIT_AT | BIT_UP;
        AuthenticatorData authenticatorData = new AuthenticatorData();
        authenticatorData.setRpIdHash(rpIdHash);
        authenticatorData.setFlags(flag);
        authenticatorData.setCounter(0);
        authenticatorData.setAttestedCredentialData(attestedCredentialData);
        authenticatorData.setExtensions(null);

        AttestationObject attestationObject = new AttestationObject(authenticatorData, attestationStatement);

        byte[] collectedClientDataBytes = collectedClientDataConverter.convertToBytes(collectedClientData);
        byte[] attestationObjectBytes = attestationObjectConverter.convertToBytes(attestationObject);
        return new WebAuthnRegistrationRequest(collectedClientDataBytes, attestationObjectBytes);
    }

    public WebAuthnAuthenticationRequest authenticate(PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions,
                                                      CollectedClientData collectedClientData,
                                                      PublicKeyCredentialDescriptor credentialDescriptor){
        byte[] collectedClientDataBytes = collectedClientDataConverter.convertToBytes(collectedClientData);
        String rpId = publicKeyCredentialRequestOptions.getRpId();

        byte[] rpIdHash = MessageDigestUtil.createSHA256().digest(rpId.getBytes(StandardCharsets.UTF_8));;
        byte control = 0x00;
        byte[] challenge = MessageDigestUtil.createSHA256().digest(collectedClientDataBytes);
        byte[] applicationParameter = rpIdHash;
        byte[] keyHandle = credentialDescriptor.getId();

        AuthenticationRequest authenticationRequest = new AuthenticationRequest(control, challenge, applicationParameter, keyHandle);

        AuthenticationResponse authenticationResponse = fidoU2FAuthenticator.authenticate(authenticationRequest);

        String credentialId = rpId;
        AuthenticatorData authenticatorData = new AuthenticatorData();
        authenticatorData.setRpIdHash(rpIdHash);
        authenticatorData.setFlags(authenticationResponse.getUserPresense());
        authenticatorData.setCounter(ByteBuffer.allocate(8).put(new byte[4]).put(authenticationResponse.getCounter()).getLong(0));
        authenticatorData.setAttestedCredentialData(null); //always null for authenticate
        authenticatorData.setExtensions(null);

        byte[] authenticatorDataBytes = authenticatorDataConverter.convertToBytes(authenticatorData);
        byte[] signature = authenticationResponse.getSignature();
        return new WebAuthnAuthenticationRequest(credentialId, collectedClientDataBytes, authenticatorDataBytes, signature);
    }

    private ESCredentialPublicKey convertToEsCredentialPublicKey(byte[] publicKey) {
        byte[] x = Arrays.copyOfRange(publicKey, 1, 1 + 32);
        byte[] y = Arrays.copyOfRange(publicKey, 1 + 32, 1 + 32 + 32);
        return new ESCredentialPublicKey(
                0,
                null,
                null,
                null,
                ESSignatureAlgorithm.SHA256withECDSA,
                Curve.SECP256R1,
                x,
                y,
                null
        );
    }

}
