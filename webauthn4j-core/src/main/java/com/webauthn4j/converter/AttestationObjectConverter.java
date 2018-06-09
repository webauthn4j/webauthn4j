package com.webauthn4j.converter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.webauthn4j.attestation.AttestationObject;
import com.webauthn4j.converter.jackson.ObjectMapperUtil;
import com.webauthn4j.util.Base64UrlUtil;

import java.io.IOException;
import java.io.UncheckedIOException;

public class AttestationObjectConverter {

    private ObjectMapper objectMapper;

    public AttestationObject convert(String source) {
        byte[] value = Base64UrlUtil.decode(source);
        return convert(value);
    }

    public AttestationObject convert(byte[] source) {
        try {
            return getCborMapper().readValue(source, AttestationObject.class);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public byte[] convertToBytes(AttestationObject source) {
        try {
            return getCborMapper().writeValueAsBytes(source);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public String convertToString(AttestationObject source) {
        byte[] bytes = convertToBytes(source);
        return Base64UrlUtil.encodeToString(bytes);
    }

    private ObjectMapper getCborMapper() {
        if (this.objectMapper == null) {
            this.objectMapper = ObjectMapperUtil.createCBORMapper();
        }
        return this.objectMapper;
    }

}
