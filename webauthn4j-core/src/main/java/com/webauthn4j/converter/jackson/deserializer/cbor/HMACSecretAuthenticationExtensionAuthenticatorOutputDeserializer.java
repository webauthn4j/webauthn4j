package com.webauthn4j.converter.jackson.deserializer.cbor;

import com.webauthn4j.data.extension.authenticator.HMACSecretAuthenticationExtensionAuthenticatorOutput;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

import java.util.Set;

public class HMACSecretAuthenticationExtensionAuthenticatorOutputDeserializer extends ExtensionAuthenticatorOutputDeserializer<HMACSecretAuthenticationExtensionAuthenticatorOutput> {

    public HMACSecretAuthenticationExtensionAuthenticatorOutputDeserializer() {
        super(HMACSecretAuthenticationExtensionAuthenticatorOutput.class);
    }

    @Override
    public @NotNull Set<String> getKeys() {
        return Set.of(HMACSecretAuthenticationExtensionAuthenticatorOutput.KEY_HMAC_SECRET);
    }

    @Override
    public HMACSecretAuthenticationExtensionAuthenticatorOutput deserialize(JsonParser p, DeserializationContext ctxt) {
        ObjectNode node = (ObjectNode) p.readValueAsTree();
        JsonNode value = node.get(HMACSecretAuthenticationExtensionAuthenticatorOutput.KEY_HMAC_SECRET);
        if (value == null || value.isNull()) return null;
        if (value.isBoolean()) return null;
        byte[] bytes = ctxt.readTreeAsValue(value, byte[].class);
        return new HMACSecretAuthenticationExtensionAuthenticatorOutput(bytes);
    }
}
