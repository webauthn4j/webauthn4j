package com.webauthn4j.converter.jackson.deserializer.json;

import com.webauthn4j.data.UserVerificationMethod;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.deser.std.StdDeserializer;

import java.util.EnumSet;
import java.util.Set;

public class UserVerificationMethodSetFromLongDeserializer extends StdDeserializer<Set<UserVerificationMethod>> {

    public UserVerificationMethodSetFromLongDeserializer() {
        super(Set.class);
    }

    @Override
    public @Nullable Set<UserVerificationMethod> deserialize(@NotNull JsonParser p, @NotNull DeserializationContext ctxt) {
        long bitmask = p.getLongValue();
        EnumSet<UserVerificationMethod> result = EnumSet.noneOf(UserVerificationMethod.class);
        for (UserVerificationMethod method : UserVerificationMethod.values()) {
            if ((bitmask & method.getValue()) != 0) {
                result.add(method);
            }
        }
        return result;
    }
}
