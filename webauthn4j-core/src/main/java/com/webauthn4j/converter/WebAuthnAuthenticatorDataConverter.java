package com.webauthn4j.converter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.webauthn4j.attestation.authenticator.WebAuthnAuthenticatorData;

import java.io.IOException;
import java.io.UncheckedIOException;

public class WebAuthnAuthenticatorDataConverter {

    private ObjectMapper objectMapper;

    public WebAuthnAuthenticatorDataConverter() {
        objectMapper = new ObjectMapper(new CBORFactory());
        objectMapper.registerModule(new WebAuthnModule());
    }

    public byte[] convertToBytes(WebAuthnAuthenticatorData source) {
        try {
            return objectMapper.writeValueAsBytes(source);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

}
