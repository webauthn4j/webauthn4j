package com.webauthn4j.converter.jackson.serializer.json;

import com.webauthn4j.data.SignatureAlgorithm;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonGenerator;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.ser.std.StdSerializer;

public class SignatureAlgorithmSerializer extends StdSerializer<SignatureAlgorithm> {

    public SignatureAlgorithmSerializer() {
        super(SignatureAlgorithm.class);
    }

    @Override
    public void serialize(@NotNull SignatureAlgorithm value, @NotNull JsonGenerator gen, @NotNull SerializationContext ctxt) {
        gen.writeString(value.serialize());
    }
}
