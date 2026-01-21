package com.webauthn4j.converter.jackson.deserializer.json;

import com.webauthn4j.data.AuthenticationAlgorithm;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.deser.std.StdDeserializer;
import tools.jackson.databind.exc.InvalidFormatException;

public class AuthenticationAlgorithmFromIntDeserializer extends StdDeserializer<AuthenticationAlgorithm> {

    public AuthenticationAlgorithmFromIntDeserializer() {
        super(AuthenticationAlgorithm.class);
    }

    @Override
    public AuthenticationAlgorithm deserialize(@NotNull JsonParser p, @NotNull DeserializationContext ctxt) {
        int value = p.getValueAsInt();
        try {
            return AuthenticationAlgorithm.create(value);
        } catch (IllegalArgumentException e) {
            throw new InvalidFormatException(null, "value is out of range", value, AuthenticationAlgorithm.class);
        }
    }
}
