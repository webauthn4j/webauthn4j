package com.webauthn4j.converter.util;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.webauthn4j.converter.jackson.WebAuthnJWSModule;

public class JWSConverter extends AbstractJsonConverter {
    public final static JWSConverter INSTANCE = new JWSConverter();

    private JWSConverter() {
        super(new ObjectMapper(new JsonFactory()), new WebAuthnJWSModule());
    }
}
