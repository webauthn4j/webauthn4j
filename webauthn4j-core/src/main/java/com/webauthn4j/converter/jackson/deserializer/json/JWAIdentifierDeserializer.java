package com.webauthn4j.converter.jackson.deserializer.json;

import com.webauthn4j.data.jws.JWAIdentifier;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.deser.std.StdDeserializer;
import tools.jackson.databind.exc.InvalidFormatException;

public class JWAIdentifierDeserializer extends StdDeserializer<JWAIdentifier> {

    public JWAIdentifierDeserializer() {
        super(JWAIdentifier.class);
    }

    @Override
    public JWAIdentifier deserialize(@NotNull JsonParser p, @NotNull DeserializationContext ctxt) {
        String value = p.getValueAsString();
        try {
            return JWAIdentifier.create(value);
        } catch (IllegalArgumentException e) {
            throw new InvalidFormatException(p, "value is out of range", value, JWAIdentifier.class);
        }
    }
}
