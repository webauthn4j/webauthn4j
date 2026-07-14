package com.webauthn4j.converter.jackson.deserializer.cbor;

import com.webauthn4j.data.extension.UvmEntries;
import com.webauthn4j.data.extension.authenticator.UserVerificationMethodExtensionAuthenticatorOutput;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

import java.util.Set;

public class UserVerificationMethodExtensionAuthenticatorOutputDeserializer extends ExtensionAuthenticatorOutputDeserializer<UserVerificationMethodExtensionAuthenticatorOutput> {

    public UserVerificationMethodExtensionAuthenticatorOutputDeserializer() {
        super(UserVerificationMethodExtensionAuthenticatorOutput.class);
    }

    @Override
    public @NotNull Set<String> getKeys() {
        return Set.of(UserVerificationMethodExtensionAuthenticatorOutput.KEY_UVM);
    }

    @Override
    public UserVerificationMethodExtensionAuthenticatorOutput deserialize(JsonParser p, DeserializationContext ctxt) {
        ObjectNode node = p.readValueAsTree();
        JsonNode value = node.get(UserVerificationMethodExtensionAuthenticatorOutput.KEY_UVM);
        if (value == null || value.isNull()) return null;
        UvmEntries uvmEntries = ctxt.readTreeAsValue(value, UvmEntries.class);
        return new UserVerificationMethodExtensionAuthenticatorOutput(uvmEntries);
    }
}
