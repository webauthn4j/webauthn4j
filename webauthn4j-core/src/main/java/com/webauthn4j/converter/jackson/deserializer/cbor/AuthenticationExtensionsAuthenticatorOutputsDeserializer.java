package com.webauthn4j.converter.jackson.deserializer.cbor;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.deser.std.StdDeserializer;
import tools.jackson.databind.node.ObjectNode;

/**
 * Custom deserializer for {@link AuthenticationExtensionsAuthenticatorOutputs} that preserves
 * the raw CBOR data as an {@link ObjectNode} for lazy resolution via deserializers.
 */
public class AuthenticationExtensionsAuthenticatorOutputsDeserializer extends StdDeserializer<AuthenticationExtensionsAuthenticatorOutputs<?>> {

    private final ObjectConverter objectConverter;

    public AuthenticationExtensionsAuthenticatorOutputsDeserializer(@NotNull ObjectConverter objectConverter) {
        super(AuthenticationExtensionsAuthenticatorOutputs.class);
        this.objectConverter = objectConverter;
    }

    @Override
    public AuthenticationExtensionsAuthenticatorOutputs<?> deserialize(JsonParser p, DeserializationContext ctxt) {
        ObjectNode node = (ObjectNode) p.readValueAsTree();
        return new AuthenticationExtensionsAuthenticatorOutputs<>(node, objectConverter);
    }
}
