package com.webauthn4j.converter.jackson.deserializer.json;

import com.webauthn4j.data.client.Origin;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.deser.std.StdDeserializer;
import tools.jackson.databind.exc.InvalidFormatException;

public class OriginDeserializer extends StdDeserializer<Origin> {

    public OriginDeserializer() {
        super(Origin.class);
    }

    @Override
    public Origin deserialize(@NotNull JsonParser p, @NotNull DeserializationContext ctxt) {
        String value = p.getValueAsString();
        try {
            return Origin.create(value);
        } catch (IllegalArgumentException e) {
            throw new InvalidFormatException(p, "value has an invalid syntax:'" + value + "'", value, Origin.class);
        }
    }
}
