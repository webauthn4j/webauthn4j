package com.webauthn4j.metadata.converter.jackson.deserializer;

import com.webauthn4j.metadata.data.toc.AuthenticatorStatus;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.deser.std.StdDeserializer;
import tools.jackson.databind.exc.InvalidFormatException;

public class AuthenticatorStatusDeserializer extends StdDeserializer<AuthenticatorStatus> {

    public AuthenticatorStatusDeserializer() {
        super(AuthenticatorStatus.class);
    }

    @Override
    public AuthenticatorStatus deserialize(@NotNull JsonParser p, @NotNull DeserializationContext ctxt) {
        String value = p.getValueAsString();
        try {
            return AuthenticatorStatus.create(value);
        } catch (IllegalArgumentException e) {
            throw new InvalidFormatException(p, "value is out of range", value, AuthenticatorStatus.class);
        }
    }
}
