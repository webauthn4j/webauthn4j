package com.webauthn4j.converter.jackson.serializer.json;

import com.webauthn4j.data.attestation.statement.COSEKeyType;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonGenerator;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.ser.std.StdSerializer;

public class COSEKeyTypeSerializer extends StdSerializer<COSEKeyType> {

    public COSEKeyTypeSerializer() {
        super(COSEKeyType.class);
    }

    @Override
    public void serialize(@NotNull COSEKeyType value, @NotNull JsonGenerator gen, @NotNull SerializationContext ctxt) {
        gen.writeNumber(value.getValue());
    }
}
