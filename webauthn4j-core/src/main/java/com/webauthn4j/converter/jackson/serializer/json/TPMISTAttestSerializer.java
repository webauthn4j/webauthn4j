package com.webauthn4j.converter.jackson.serializer.json;

import com.webauthn4j.data.attestation.statement.TPMISTAttest;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonGenerator;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.ser.std.StdSerializer;

/**
 * @deprecated TPM types are serialized as raw byte arrays, not through Jackson's type system.
 *             This serializer was created for consistency but has no real use case and will be removed.
 */
@Deprecated
public class TPMISTAttestSerializer extends StdSerializer<TPMISTAttest> {

    public TPMISTAttestSerializer() {
        super(TPMISTAttest.class);
    }

    @Override
    public void serialize(@NotNull TPMISTAttest value, @NotNull JsonGenerator gen, @NotNull SerializationContext ctxt) {
        ctxt.writeValue(gen, value.getValue());
    }
}
