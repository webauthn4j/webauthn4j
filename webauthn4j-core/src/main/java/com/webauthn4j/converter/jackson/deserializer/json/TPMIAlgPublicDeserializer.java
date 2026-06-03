package com.webauthn4j.converter.jackson.deserializer.json;

import com.webauthn4j.data.attestation.statement.TPMIAlgPublic;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.deser.std.StdDeserializer;
import tools.jackson.databind.exc.InvalidFormatException;

/**
 * @deprecated TPM types are parsed from raw byte arrays, not through Jackson's type system.
 *             This deserializer was created for consistency but has no real use case and will be removed.
 */
@Deprecated
public class TPMIAlgPublicDeserializer extends StdDeserializer<TPMIAlgPublic> {

    public TPMIAlgPublicDeserializer() {
        super(TPMIAlgPublic.class);
    }

    @Override
    public TPMIAlgPublic deserialize(@NotNull JsonParser p, @NotNull DeserializationContext ctxt) {
        int value = p.getValueAsInt();
        try {
            return TPMIAlgPublic.create(value);
        } catch (IllegalArgumentException e) {
            throw new InvalidFormatException(p, "value is out of range", value, TPMIAlgPublic.class);
        }
    }
}
