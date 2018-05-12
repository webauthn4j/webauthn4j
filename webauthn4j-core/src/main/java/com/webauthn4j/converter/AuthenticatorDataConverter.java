package com.webauthn4j.converter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.webauthn4j.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.attestation.authenticator.CredentialPublicKey;
import com.webauthn4j.attestation.authenticator.extension.Extension;
import com.webauthn4j.converter.jackson.ObjectMapperUtil;
import com.webauthn4j.util.UnsignedNumberUtil;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.List;

public class AuthenticatorDataConverter {

    private ObjectMapper objectMapper;

    public AuthenticatorDataConverter() {
        objectMapper = ObjectMapperUtil.createCBORMapper();
    }

    public byte[] convertToBytes(AuthenticatorData source) {
        try {
            return serialize(source);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    byte[] serialize(AuthenticatorData value) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byte[] rpIdHash = value.getRpIdHash();
        byteArrayOutputStream.write(rpIdHash);
        byteArrayOutputStream.write(new byte[]{value.getFlags()});
        byteArrayOutputStream.write(UnsignedNumberUtil.toBytes(value.getSignCount()));
        if (value.getAttestedCredentialData() != null) {
            byteArrayOutputStream.write(serializeAttestedCredentialData(value.getAttestedCredentialData()));
        }
        byteArrayOutputStream.write(serializeExtensions(value.getExtensions()));
        return byteArrayOutputStream.toByteArray();
    }

    private byte[] serializeAttestedCredentialData(AttestedCredentialData attestationData) throws IOException {

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
