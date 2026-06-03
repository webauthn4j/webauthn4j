package com.webauthn4j.converter.jackson.serializer.json;

import com.webauthn4j.data.attestation.statement.TPMGenerated;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonGenerator;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.ser.std.StdSerializer;

/**
 * @deprecated TPM types are serialized as raw byte arrays, not through Jackson's type system.
 *             This serializer was created for consistency but has no real use case and will be removed.
 */
@Deprecated
public class TPMGeneratedSerializer extends StdSerializer<TPMGenerated> {

    public TPMGeneratedSerializer() {
        super(TPMGenerated.class);
    }

    @Override
    public void serialize(@NotNull TPMGenerated value, @NotNull JsonGenerator gen, @NotNull SerializationContext ctxt) {
        ctxt.writeValue(gen, value.getValue());
    }
}
