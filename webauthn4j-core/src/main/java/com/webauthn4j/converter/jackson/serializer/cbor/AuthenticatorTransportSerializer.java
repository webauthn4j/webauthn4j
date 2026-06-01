package com.webauthn4j.converter.jackson.serializer.cbor;

import com.webauthn4j.data.AuthenticatorTransport;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonGenerator;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.ser.std.StdSerializer;

public class AuthenticatorTransportSerializer extends StdSerializer<AuthenticatorTransport> {

    public AuthenticatorTransportSerializer() {
        super(AuthenticatorTransport.class);
    }

    @Override
    public void serialize(@NotNull AuthenticatorTransport value, @NotNull JsonGenerator gen, @NotNull SerializationContext ctxt) {
        gen.writeString(value.getValue());
    }
}
