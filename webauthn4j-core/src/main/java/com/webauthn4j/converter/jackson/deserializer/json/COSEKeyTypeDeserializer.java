package com.webauthn4j.converter.jackson.deserializer.json;

import com.webauthn4j.data.attestation.statement.COSEKeyType;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.deser.std.StdDeserializer;
import tools.jackson.databind.exc.InvalidFormatException;

public class COSEKeyTypeDeserializer extends StdDeserializer<COSEKeyType> {

    public COSEKeyTypeDeserializer() {
        super(COSEKeyType.class);
    }

    @Override
    public COSEKeyType deserialize(@NotNull JsonParser p, @NotNull DeserializationContext ctxt) {
        int value = p.getValueAsInt();
        try {
            return COSEKeyType.create(value);
        } catch (IllegalArgumentException e) {
            throw new InvalidFormatException(p, "value is out of range", value, COSEKeyType.class);
        }
    }
}
