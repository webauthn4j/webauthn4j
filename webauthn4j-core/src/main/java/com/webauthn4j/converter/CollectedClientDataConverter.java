package com.webauthn4j.converter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.webauthn4j.client.CollectedClientData;
import com.webauthn4j.util.Base64UrlUtil;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class CollectedClientDataConverter {

    private ObjectMapper objectMapper;

    public CollectedClientDataConverter() {
        objectMapper = new ObjectMapper();
        objectMapper.registerModule(new WebAuthnModule());
    }

    public CollectedClientData convert(String base64UrlString) {
        byte[] bytes = Base64UrlUtil.decode(base64UrlString);
        return convert(bytes);
    }

    public CollectedClientData convert(byte[] source) {
        String jsonString = new String(source, StandardCharsets.UTF_8);
        try {
            return objectMapper.readValue(jsonString, CollectedClientData.class);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public byte[] convertToBytes(CollectedClientData source) {
        try {
            return objectMapper.writeValueAsBytes(source);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public String convertToString(CollectedClientData source) {
        byte[] bytes = convertToBytes(source);
        return Base64UrlUtil.encodeToString(bytes);
    }

}
