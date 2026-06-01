package com.webauthn4j.converter.jackson.deserializer.json;

import com.webauthn4j.data.attestation.statement.TPMIAlgHash;
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
public class TPMIAlgHashDeserializer extends StdDeserializer<TPMIAlgHash> {

    public TPMIAlgHashDeserializer() {
        super(TPMIAlgHash.class);
    }

    @Override
    public TPMIAlgHash deserialize(@NotNull JsonParser p, @NotNull DeserializationContext ctxt) {
        int value = p.getValueAsInt();
        try {
            return TPMIAlgHash.create(value);
        } catch (IllegalArgumentException e) {
            throw new InvalidFormatException(p, "value is out of range", value, TPMIAlgHash.class);
        }
    }
}
