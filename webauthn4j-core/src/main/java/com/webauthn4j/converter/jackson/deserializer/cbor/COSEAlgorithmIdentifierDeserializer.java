package com.webauthn4j.converter.jackson.deserializer.cbor;

import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonParser;
import tools.jackson.core.JsonToken;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.deser.std.StdDeserializer;
import tools.jackson.databind.exc.InvalidFormatException;

public class COSEAlgorithmIdentifierDeserializer extends StdDeserializer<COSEAlgorithmIdentifier> {

    public COSEAlgorithmIdentifierDeserializer() {
        super(COSEAlgorithmIdentifier.class);
    }

    @Override
    public COSEAlgorithmIdentifier deserialize(@NotNull JsonParser p, @NotNull DeserializationContext ctxt) {
        if (p.currentToken() != JsonToken.VALUE_NUMBER_INT) {
            throw InvalidFormatException.from(p, "Expected an integer value for COSEAlgorithmIdentifier", p.getText(), COSEAlgorithmIdentifier.class);
        }
        long value = p.getValueAsLong();
        return COSEAlgorithmIdentifier.create(value);
    }
}
