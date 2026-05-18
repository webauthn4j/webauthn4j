package com.webauthn4j.converter.jackson.deserializer.cbor;

import com.webauthn4j.data.extension.authenticator.HMACGetSecretAuthenticatorInput;
import com.webauthn4j.data.extension.authenticator.HMACSecretAuthenticationExtensionAuthenticatorInput;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

import java.util.Set;

public class HMACSecretAuthenticationExtensionAuthenticatorInputDeserializer extends ExtensionAuthenticatorInputDeserializer<HMACSecretAuthenticationExtensionAuthenticatorInput> {

    public HMACSecretAuthenticationExtensionAuthenticatorInputDeserializer() {
        super(HMACSecretAuthenticationExtensionAuthenticatorInput.class);
    }

    @Override
    public @NotNull Set<String> getKeys() {
        return Set.of(HMACSecretAuthenticationExtensionAuthenticatorInput.KEY_HMAC_SECRET);
    }

    @Override
    public HMACSecretAuthenticationExtensionAuthenticatorInput deserialize(JsonParser p, DeserializationContext ctxt) {
        ObjectNode node = (ObjectNode) p.readValueAsTree();
        JsonNode value = node.get(HMACSecretAuthenticationExtensionAuthenticatorInput.KEY_HMAC_SECRET);
        if (value == null || value.isNull()) return null;
        if (value.isBoolean()) return null;
        HMACGetSecretAuthenticatorInput hmacGetSecret = ctxt.readTreeAsValue(value, HMACGetSecretAuthenticatorInput.class);
        return new HMACSecretAuthenticationExtensionAuthenticatorInput(hmacGetSecret);
    }
}
