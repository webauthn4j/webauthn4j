package com.webauthn4j.converter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.webauthn4j.attestation.WebAuthnAttestationObject;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.Base64;

public class WebAuthnAttestationObjectConverter {

    private ObjectMapper objectMapper;

    public WebAuthnAttestationObjectConverter() {
        objectMapper = new ObjectMapper(new CBORFactory());
        objectMapper.registerModule(new WebAuthnModule());
    }

    public WebAuthnAttestationObject convert(String source) {
        byte[] value = java.util.Base64.getUrlDecoder().decode(source);
        return convert(value);
    }

    public WebAuthnAttestationObject convert(byte[] source){
        try {
            return objectMapper.readValue(source, WebAuthnAttestationObject.class);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public byte[] convertToBytes(WebAuthnAttestationObject source) {
        try {
            return objectMapper.writeValueAsBytes(source);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public String convertToString(WebAuthnAttestationObject source) {
        byte[] bytes = convertToBytes(source);
        return Base64.getUrlEncoder().encodeToString(bytes);
    }

}
