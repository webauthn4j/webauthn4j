package com.webauthn4j.metadata.converter.jackson.deserializer;

import com.webauthn4j.metadata.data.uaf.AAID;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.deser.std.StdDeserializer;
import tools.jackson.databind.exc.InvalidFormatException;

public class AAIDDeserializer extends StdDeserializer<AAID> {

    public AAIDDeserializer() {
        super(AAID.class);
    }

    @Override
    public AAID deserialize(@NotNull JsonParser p, @NotNull DeserializationContext ctxt) {
        String value = p.getValueAsString();
        try {
            return new AAID(value);
        } catch (IllegalArgumentException e) {
            throw new InvalidFormatException(p, "invalid aaid", value, AAID.class);
        }
    }
}
