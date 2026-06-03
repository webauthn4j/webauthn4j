package com.webauthn4j.converter.jackson.serializer.json;

import com.webauthn4j.data.attestation.statement.COSEKeyOperation;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonGenerator;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.ser.std.StdSerializer;

public class COSEKeyOperationSerializer extends StdSerializer<COSEKeyOperation> {

    public COSEKeyOperationSerializer() {
        super(COSEKeyOperation.class);
    }

    @Override
    public void serialize(@NotNull COSEKeyOperation value, @NotNull JsonGenerator gen, @NotNull SerializationContext ctxt) {
        gen.writeNumber(value.getValue());
    }
}
