package com.webauthn4j.converter.jackson.deserializer.json;

import com.webauthn4j.data.attestation.authenticator.Curve;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.deser.std.StdDeserializer;
import tools.jackson.databind.exc.InvalidFormatException;

public class CurveDeserializer extends StdDeserializer<Curve> {

    public CurveDeserializer() {
        super(Curve.class);
    }

    @Override
    public Curve deserialize(@NotNull JsonParser p, @NotNull DeserializationContext ctxt) {
        int value = p.getValueAsInt();
        try {
            return Curve.create(value);
        } catch (IllegalArgumentException e) {
            throw new InvalidFormatException(p, "value is out of range", value, Curve.class);
        }
    }
}
