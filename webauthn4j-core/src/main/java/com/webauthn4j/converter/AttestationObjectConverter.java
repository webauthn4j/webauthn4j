package com.webauthn4j.converter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.webauthn4j.attestation.AttestationObject;
import com.webauthn4j.util.Base64UrlUtil;

import java.io.IOException;
import java.io.UncheckedIOException;

public class AttestationObjectConverter {

    private ObjectMapper objectMapper;

    public AttestationObjectConverter() {
        objectMapper = new ObjectMapper(new CBORFactory());
        objectMapper.registerModule(new WebAuthnModule());
    }

    public AttestationObject convert(String source) {
        byte[] value = Base64UrlUtil.decode(source);
        return convert(value);
    }

    public AttestationObject convert(byte[] source) {
        try {
            return objectMapper.readValue(source, AttestationObject.class);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public byte[] convertToBytes(AttestationObject source) {
        try {
            return objectMapper.writeValueAsBytes(source);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public String convertToString(AttestationObject source) {
        byte[] bytes = convertToBytes(source);
        return Base64UrlUtil.encodeToString(bytes);
    }

}
