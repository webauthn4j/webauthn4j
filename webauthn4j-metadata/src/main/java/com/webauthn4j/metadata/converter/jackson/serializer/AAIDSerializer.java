package com.webauthn4j.metadata.converter.jackson.serializer;

import com.webauthn4j.metadata.data.uaf.AAID;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonGenerator;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.ser.std.StdSerializer;

public class AAIDSerializer extends StdSerializer<AAID> {

    public AAIDSerializer() {
        super(AAID.class);
    }

    @Override
    public void serialize(@NotNull AAID value, @NotNull JsonGenerator gen, @NotNull SerializationContext ctxt) {
        gen.writeString(value.toString());
    }
}
