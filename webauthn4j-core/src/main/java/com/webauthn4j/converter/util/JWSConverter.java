package com.webauthn4j.converter.util;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.webauthn4j.converter.jackson.WebAuthnJWSModule;

public class JWSConverter extends AbstractJsonConverter {
    public final static JWSConverter INSTANCE = new JWSConverter();

    private JWSConverter() {
        this.jsonMapper = new ObjectMapper(new JsonFactory());

        this.jsonMapper.registerModule(new WebAuthnJWSModule());
        this.jsonMapper.configure(DeserializationFeature.WRAP_EXCEPTIONS, false);
        this.jsonMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        this.jsonMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
    }
}
