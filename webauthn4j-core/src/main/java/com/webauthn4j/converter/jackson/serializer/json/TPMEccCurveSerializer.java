package com.webauthn4j.converter.jackson.serializer.json;

import com.webauthn4j.data.attestation.statement.TPMEccCurve;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonGenerator;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.ser.std.StdSerializer;

/**
 * @deprecated TPM types are serialized as raw byte arrays, not through Jackson's type system.
 *             This serializer was created for consistency but has no real use case and will be removed.
 */
@Deprecated
public class TPMEccCurveSerializer extends StdSerializer<TPMEccCurve> {

    public TPMEccCurveSerializer() {
        super(TPMEccCurve.class);
    }

    @Override
    public void serialize(@NotNull TPMEccCurve value, @NotNull JsonGenerator gen, @NotNull SerializationContext ctxt) {
        gen.writeNumber(value.getValue());
    }
}
