package com.webauthn4j.converter.jackson.deserializer.cbor;

import com.webauthn4j.data.extension.authenticator.HMACSecretRegistrationExtensionAuthenticatorOutput;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

import java.util.Set;

public class HMACSecretRegistrationExtensionAuthenticatorOutputDeserializer extends ExtensionAuthenticatorOutputDeserializer<HMACSecretRegistrationExtensionAuthenticatorOutput> {

    public HMACSecretRegistrationExtensionAuthenticatorOutputDeserializer() {
        super(HMACSecretRegistrationExtensionAuthenticatorOutput.class);
    }

    @Override
    public @NotNull Set<String> getKeys() {
        return Set.of(HMACSecretRegistrationExtensionAuthenticatorOutput.KEY_HMAC_SECRET);
    }

    @Override
    public HMACSecretRegistrationExtensionAuthenticatorOutput deserialize(JsonParser p, DeserializationContext ctxt) {
        ObjectNode node = p.readValueAsTree();
        JsonNode value = node.get(HMACSecretRegistrationExtensionAuthenticatorOutput.KEY_HMAC_SECRET);
        if (value == null || value.isNull()) return null;
        if (!value.isBoolean()) return null;
        return new HMACSecretRegistrationExtensionAuthenticatorOutput(value.asBoolean());
    }
}
