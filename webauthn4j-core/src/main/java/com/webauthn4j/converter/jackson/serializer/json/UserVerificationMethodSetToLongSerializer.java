package com.webauthn4j.converter.jackson.serializer.json;

import com.webauthn4j.data.UserVerificationMethod;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonGenerator;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.ser.std.StdSerializer;

import java.util.Set;

public class UserVerificationMethodSetToLongSerializer extends StdSerializer<Set<UserVerificationMethod>> {

    public UserVerificationMethodSetToLongSerializer() {
        super(Set.class);
    }

    @Override
    public void serialize(@NotNull Set<UserVerificationMethod> value, @NotNull JsonGenerator gen, @NotNull SerializationContext ctxt) {
        long bitmask = 0;
        for (UserVerificationMethod method : value) {
            bitmask |= method.getValue();
        }
        gen.writeNumber(bitmask);
    }
}
