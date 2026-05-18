package com.webauthn4j.converter.jackson.deserializer.json;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.deser.std.StdDeserializer;
import tools.jackson.databind.node.ObjectNode;

/**
 * Custom deserializer for {@link AuthenticationExtensionsClientInputs} that preserves
 * the raw JSON as an {@link ObjectNode} for lazy resolution via deserializers.
 */
public class AuthenticationExtensionsClientInputsDeserializer extends StdDeserializer<AuthenticationExtensionsClientInputs<?>> {

    private final ObjectConverter objectConverter;

    public AuthenticationExtensionsClientInputsDeserializer(@NotNull ObjectConverter objectConverter) {
        super(AuthenticationExtensionsClientInputs.class);
        this.objectConverter = objectConverter;
    }

    @Override
    public AuthenticationExtensionsClientInputs<?> deserialize(JsonParser p, DeserializationContext ctxt) {
        ObjectNode node = (ObjectNode) p.readValueAsTree();
        return new AuthenticationExtensionsClientInputs<>(node, objectConverter);
    }
}
