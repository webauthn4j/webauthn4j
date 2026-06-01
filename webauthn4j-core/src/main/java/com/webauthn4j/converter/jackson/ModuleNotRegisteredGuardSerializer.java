package com.webauthn4j.converter.jackson;

import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonGenerator;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.ser.std.StdSerializer;

public class ModuleNotRegisteredGuardSerializer extends StdSerializer<Object> {

    public ModuleNotRegisteredGuardSerializer() {
        super(Object.class);
    }

    @Override
    public void serialize(@NotNull Object value, @NotNull JsonGenerator gen, @NotNull SerializationContext ctxt) {
        throw new IllegalStateException(String.format(
                "%s requires a WebAuthn Jackson module (e.g. WebAuthnJSONModule, WebAuthnCBORModule) to be registered. Use ObjectConverter.",
                value.getClass().getSimpleName()));
    }
}
