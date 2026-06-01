package com.webauthn4j.converter.jackson.deserializer.json;

import com.webauthn4j.data.AuthenticatorTransport;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonParser;
import tools.jackson.core.JsonToken;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.deser.std.StdDeserializer;
import tools.jackson.databind.exc.MismatchedInputException;

public class AuthenticatorTransportDeserializer extends StdDeserializer<AuthenticatorTransport> {

    public AuthenticatorTransportDeserializer() {
        super(AuthenticatorTransport.class);
    }

    @Override
    public AuthenticatorTransport deserialize(@NotNull JsonParser p, @NotNull DeserializationContext ctxt) {
        if (p.currentToken() != JsonToken.VALUE_STRING) {
            throw MismatchedInputException.from(p, AuthenticatorTransport.class,
                    "Expected a string value for AuthenticatorTransport");
        }
        String value = p.getValueAsString();
        return AuthenticatorTransport.create(value);
    }

    @Override
    public AuthenticatorTransport getNullValue(@NotNull DeserializationContext ctxt) {
        throw MismatchedInputException.from(ctxt.getParser(), AuthenticatorTransport.class,
                "null is not allowed for AuthenticatorTransport");
    }
}
