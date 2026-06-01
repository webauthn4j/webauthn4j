package com.webauthn4j.converter.jackson.serializer.json;

import com.webauthn4j.data.attestation.statement.TPMIAlgPublic;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonGenerator;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.ser.std.StdSerializer;

/**
 * @deprecated TPM types are serialized as raw byte arrays, not through Jackson's type system.
 *             This serializer was created for consistency but has no real use case and will be removed.
 */
@Deprecated
public class TPMIAlgPublicSerializer extends StdSerializer<TPMIAlgPublic> {

    public TPMIAlgPublicSerializer() {
        super(TPMIAlgPublic.class);
    }

    @Override
    public void serialize(@NotNull TPMIAlgPublic value, @NotNull JsonGenerator gen, @NotNull SerializationContext ctxt) {
        gen.writeNumber(value.getValue());
    }
}
