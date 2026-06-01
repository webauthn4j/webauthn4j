package com.webauthn4j.converter.jackson.deserializer.json;

import com.webauthn4j.data.MessageDigestAlgorithm;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonParser;
import tools.jackson.core.JsonToken;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.deser.std.StdDeserializer;
import tools.jackson.databind.exc.MismatchedInputException;

public class MessageDigestAlgorithmDeserializer extends StdDeserializer<MessageDigestAlgorithm> {

    public MessageDigestAlgorithmDeserializer() {
        super(MessageDigestAlgorithm.class);
    }

    @Override
    public MessageDigestAlgorithm deserialize(@NotNull JsonParser p, @NotNull DeserializationContext ctxt) {
        if (p.currentToken() != JsonToken.VALUE_STRING) {
            throw MismatchedInputException.from(p, MessageDigestAlgorithm.class,
                    "Expected a string value for MessageDigestAlgorithm");
        }
        String value = p.getValueAsString();
        return MessageDigestAlgorithm.create(value);
    }
}
