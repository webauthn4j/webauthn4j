package com.webauthn4j.converter.jackson.deserializer.cbor;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorInputs;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.deser.std.StdDeserializer;
import tools.jackson.databind.node.ObjectNode;

/**
 * Custom deserializer for {@link AuthenticationExtensionsAuthenticatorInputs} that preserves
 * the raw CBOR data as an {@link ObjectNode} for lazy resolution via deserializers.
 */
public class AuthenticationExtensionsAuthenticatorInputsDeserializer extends StdDeserializer<AuthenticationExtensionsAuthenticatorInputs<?>> {

    private final ObjectConverter objectConverter;

    public AuthenticationExtensionsAuthenticatorInputsDeserializer(@NotNull ObjectConverter objectConverter) {
        super(AuthenticationExtensionsAuthenticatorInputs.class);
        this.objectConverter = objectConverter;
    }

    @Override
    public AuthenticationExtensionsAuthenticatorInputs<?> deserialize(JsonParser p, DeserializationContext ctxt) {
        ObjectNode node = p.readValueAsTree();
        return new AuthenticationExtensionsAuthenticatorInputs<>(node, objectConverter);
    }
}
