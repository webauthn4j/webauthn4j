package com.webauthn4j.converter.jackson.serializer.json;

import com.webauthn4j.data.attestation.authenticator.Curve;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonGenerator;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.ser.std.StdSerializer;

public class CurveSerializer extends StdSerializer<Curve> {

    public CurveSerializer() {
        super(Curve.class);
    }

    @Override
    public void serialize(@NotNull Curve value, @NotNull JsonGenerator gen, @NotNull SerializationContext ctxt) {
        gen.writeNumber(value.getValue());
    }
}
