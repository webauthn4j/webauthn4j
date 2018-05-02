package com.webauthn4j.jackson;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

public class ObjectMapperUtil {

    private ObjectMapperUtil(){}

    public static ObjectMapper createJSONMapper(){
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.registerModule(new WebAuthnModule());
        objectMapper.registerModule(new JavaTimeModule()); // TODO: remove this module since it is used by extras
        objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        return objectMapper;
    }

    public static ObjectMapper createCBORMapper() {
        ObjectMapper objectMapper = new ObjectMapper(new CBORFactory());
        objectMapper.registerModule(new WebAuthnModule());
        objectMapper.registerModule(new JavaTimeModule()); // TODO: remove this module since it is used by extras
        objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        return objectMapper;
    }
}
