package com.webauthn4j.converter.jackson.serializer.json;

import com.webauthn4j.data.jws.JWAIdentifier;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonGenerator;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.ser.std.StdSerializer;

public class JWAIdentifierSerializer extends StdSerializer<JWAIdentifier> {

    public JWAIdentifierSerializer() {
        super(JWAIdentifier.class);
    }

    @Override
    public void serialize(@NotNull JWAIdentifier value, @NotNull JsonGenerator gen, @NotNull SerializationContext ctxt) {
        gen.writeString(value.getName());
    }
}
