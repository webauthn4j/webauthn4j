package com.webauthn4j.converter.jackson.deserializer.cbor;

import com.webauthn4j.data.attestation.statement.COSEKeyOperation;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.deser.std.StdDeserializer;
import tools.jackson.databind.exc.InvalidFormatException;

public class COSEKeyOperationDeserializer extends StdDeserializer<COSEKeyOperation> {

    public COSEKeyOperationDeserializer() {
        super(COSEKeyOperation.class);
    }

    @Override
    public COSEKeyOperation deserialize(@NotNull JsonParser p, @NotNull DeserializationContext ctxt) {
        int value = p.getValueAsInt();
        try {
            return COSEKeyOperation.create(value);
        } catch (IllegalArgumentException e) {
            throw new InvalidFormatException(p, "value is out of range", value, COSEKeyOperation.class);
        }
    }
}
