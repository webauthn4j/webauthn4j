package com.webauthn4j.converter.jackson.deserializer.cbor;

import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.deser.std.StdDeserializer;

public class COSEAlgorithmIdentifierDeserializer extends StdDeserializer<COSEAlgorithmIdentifier> {

    public COSEAlgorithmIdentifierDeserializer() {
        super(COSEAlgorithmIdentifier.class);
    }

    @Override
    public COSEAlgorithmIdentifier deserialize(@NotNull JsonParser p, @NotNull DeserializationContext ctxt) {
        long value = p.getValueAsLong();
        return COSEAlgorithmIdentifier.create(value);
    }
}
