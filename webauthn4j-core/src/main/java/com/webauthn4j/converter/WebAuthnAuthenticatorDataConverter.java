package com.webauthn4j.converter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.webauthn4j.attestation.authenticator.CredentialPublicKey;
import com.webauthn4j.attestation.authenticator.WebAuthnAttestedCredentialData;
import com.webauthn4j.attestation.authenticator.WebAuthnAuthenticatorData;
import com.webauthn4j.attestation.authenticator.extension.Extension;
import com.webauthn4j.util.UnsignedNumberUtil;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.List;

public class WebAuthnAuthenticatorDataConverter {

    private ObjectMapper objectMapper;

    public WebAuthnAuthenticatorDataConverter() {
        objectMapper = new ObjectMapper(new CBORFactory());
        objectMapper.registerModule(new WebAuthnModule());
    }

    public byte[] convertToBytes(WebAuthnAuthenticatorData source) {
        try {
            return serialize(source);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    byte[] serialize(WebAuthnAuthenticatorData value) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byte[] rpIdHash = value.getRpIdHash();
        byteArrayOutputStream.write(rpIdHash);
        byteArrayOutputStream.write(new byte[]{value.getFlags()});
        byteArrayOutputStream.write(UnsignedNumberUtil.toBytes(value.getCounter()));
        if (value.getAttestedCredentialData() != null) {
            byteArrayOutputStream.write(serializeAttestedCredentialData(value.getAttestedCredentialData()));
        }
        byteArrayOutputStream.write(serializeExtensions(value.getExtensions()));
        return byteArrayOutputStream.toByteArray();
    }

    private byte[] serializeAttestedCredentialData(WebAuthnAttestedCredentialData attestationData) throws IOException {

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byteArrayOutputStream.write(attestationData.getAaGuid());
        byteArrayOutputStream.write(UnsignedNumberUtil.toBytes(attestationData.getCredentialId().length));
        byteArrayOutputStream.write(attestationData.getCredentialId());
        byteArrayOutputStream.write(serializeCredentialPublicKey(attestationData.getCredentialPublicKey()));
        return byteArrayOutputStream.toByteArray();
    }

    private byte[] serializeExtensions(List<Extension> extensions) {
        return new byte[0]; //TODO: to be implemented
    }

    private byte[] serializeCredentialPublicKey(CredentialPublicKey credentialPublicKey) throws JsonProcessingException {
        return objectMapper.writeValueAsBytes(credentialPublicKey);
    }

}
