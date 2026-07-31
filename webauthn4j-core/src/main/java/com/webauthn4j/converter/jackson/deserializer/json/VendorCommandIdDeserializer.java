package com.webauthn4j.converter.jackson.deserializer.json;

import com.webauthn4j.data.VendorCommandId;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonParser;
import tools.jackson.core.JsonToken;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.deser.std.StdDeserializer;
import tools.jackson.databind.exc.InvalidFormatException;

public class VendorCommandIdDeserializer extends StdDeserializer<VendorCommandId> {

    public VendorCommandIdDeserializer() {
        super(VendorCommandId.class);
    }

    @Override
    public VendorCommandId deserialize(@NotNull JsonParser p, @NotNull DeserializationContext ctxt) {
        if (p.currentToken() != JsonToken.VALUE_NUMBER_INT) {
            throw InvalidFormatException.from(p, "Expected an integer value for VendorCommandId", p.getText(), VendorCommandId.class);
        }
        return VendorCommandId.create(p.getBigIntegerValue());
    }
}
