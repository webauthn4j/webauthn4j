package com.webauthn4j.converter.jackson;

import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.deser.std.StdDeserializer;

public class ModuleNotRegisteredGuardDeserializer extends StdDeserializer<Object> {

    public ModuleNotRegisteredGuardDeserializer() {
        super(Object.class);
    }

    @Override
    public Object deserialize(@NotNull JsonParser p, @NotNull DeserializationContext ctxt) {
        throw new IllegalStateException(String.format(
                "%s requires a WebAuthn Jackson module (e.g. WebAuthnJSONModule, WebAuthnCBORModule) to be registered. Use ObjectConverter.",
                handledType().getSimpleName()));
    }
}
