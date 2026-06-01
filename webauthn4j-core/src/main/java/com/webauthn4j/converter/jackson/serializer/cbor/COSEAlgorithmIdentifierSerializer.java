package com.webauthn4j.converter.jackson.serializer.cbor;

import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonGenerator;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.ser.std.StdSerializer;

public class COSEAlgorithmIdentifierSerializer extends StdSerializer<COSEAlgorithmIdentifier> {

    public COSEAlgorithmIdentifierSerializer() {
        super(COSEAlgorithmIdentifier.class);
    }

    @Override
    public void serialize(@NotNull COSEAlgorithmIdentifier value, @NotNull JsonGenerator gen, @NotNull SerializationContext ctxt) {
        gen.writeNumber(value.getValue());
    }
}
