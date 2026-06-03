package com.webauthn4j.metadata.converter.jackson.serializer;

import com.webauthn4j.metadata.data.toc.AuthenticatorStatus;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonGenerator;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.ser.std.StdSerializer;

public class AuthenticatorStatusSerializer extends StdSerializer<AuthenticatorStatus> {

    public AuthenticatorStatusSerializer() {
        super(AuthenticatorStatus.class);
    }

    @Override
    public void serialize(@NotNull AuthenticatorStatus value, @NotNull JsonGenerator gen, @NotNull SerializationContext ctxt) {
        gen.writeString(value.getValue());
    }
}
