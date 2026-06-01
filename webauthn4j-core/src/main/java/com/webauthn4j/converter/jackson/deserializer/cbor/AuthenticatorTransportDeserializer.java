package com.webauthn4j.converter.jackson.deserializer.cbor;

import com.webauthn4j.data.AuthenticatorTransport;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.deser.std.StdDeserializer;

public class AuthenticatorTransportDeserializer extends StdDeserializer<AuthenticatorTransport> {

    public AuthenticatorTransportDeserializer() {
        super(AuthenticatorTransport.class);
    }

    @Override
    public AuthenticatorTransport deserialize(@NotNull JsonParser p, @NotNull DeserializationContext ctxt) {
        String value = p.getValueAsString();
        return AuthenticatorTransport.create(value);
    }
}
