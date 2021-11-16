package com.webauthn4j.converter.jackson.deserializer.json;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import com.webauthn4j.data.AuthenticationAlgorithm;

import java.io.IOException;

public class AuthenticationAlgorithmFromIntDeserializer extends StdDeserializer<AuthenticationAlgorithm> {

    public AuthenticationAlgorithmFromIntDeserializer() {
        super(AuthenticationAlgorithm.class);
    }

    @Override
    public AuthenticationAlgorithm deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
        int value = p.getValueAsInt();
        try {
            return AuthenticationAlgorithm.create(value);
        } catch (IllegalArgumentException e) {
            throw new InvalidFormatException(null, "value is out of range", value, AuthenticationAlgorithm.class);
        }
    }
}
