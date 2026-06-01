package com.webauthn4j.converter.jackson.serializer.json;

import com.webauthn4j.data.MessageDigestAlgorithm;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonGenerator;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.ser.std.StdSerializer;

public class MessageDigestAlgorithmSerializer extends StdSerializer<MessageDigestAlgorithm> {

    public MessageDigestAlgorithmSerializer() {
        super(MessageDigestAlgorithm.class);
    }

    @Override
    public void serialize(@NotNull MessageDigestAlgorithm value, @NotNull JsonGenerator gen, @NotNull SerializationContext ctxt) {
        gen.writeString(value.getJcaName());
    }
}
