package com.webauthn4j.converter.jackson.serializer.json;

import com.webauthn4j.data.VendorCommandId;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonGenerator;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.ser.std.StdSerializer;

public class VendorCommandIdSerializer extends StdSerializer<VendorCommandId> {

    public VendorCommandIdSerializer() {
        super(VendorCommandId.class);
    }

    @Override
    public void serialize(@NotNull VendorCommandId value, @NotNull JsonGenerator gen, @NotNull SerializationContext ctxt) {
        gen.writeNumber(value.asBigInteger());
    }
}
