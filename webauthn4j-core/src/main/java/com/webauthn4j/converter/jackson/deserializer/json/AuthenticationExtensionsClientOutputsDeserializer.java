package com.webauthn4j.converter.jackson.deserializer.json;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.deser.std.StdDeserializer;
import tools.jackson.databind.node.ObjectNode;

/**
 * Custom deserializer for {@link AuthenticationExtensionsClientOutputs} that preserves
 * the raw JSON as an {@link ObjectNode} for lazy resolution via converters.
 */
public class AuthenticationExtensionsClientOutputsDeserializer extends StdDeserializer<AuthenticationExtensionsClientOutputs<?>> {

    private final ObjectConverter objectConverter;

    public AuthenticationExtensionsClientOutputsDeserializer(@NotNull ObjectConverter objectConverter) {
        super(AuthenticationExtensionsClientOutputs.class);
        this.objectConverter = objectConverter;
    }

    @Override
    public AuthenticationExtensionsClientOutputs<?> deserialize(JsonParser p, DeserializationContext ctxt) {
        ObjectNode node = (ObjectNode) p.readValueAsTree();
        return new AuthenticationExtensionsClientOutputs<>(node, objectConverter);
    }
}
