package com.webauthn4j.spc.converter.jackson.deserializer.json;

import com.webauthn4j.converter.jackson.deserializer.json.ExtensionClientOutputDeserializer;
import com.webauthn4j.spc.data.extension.client.AuthenticationExtensionsPaymentOutputs;
import com.webauthn4j.spc.data.extension.client.BrowserBoundSignature;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

import java.util.Set;

public class PaymentExtensionClientOutputDeserializer
        extends ExtensionClientOutputDeserializer<AuthenticationExtensionsPaymentOutputs> {

    public PaymentExtensionClientOutputDeserializer() {
        super(AuthenticationExtensionsPaymentOutputs.class);
    }

    @Override
    public @NotNull Set<String> getKeys() {
        return Set.of(AuthenticationExtensionsPaymentOutputs.KEY_PAYMENT);
    }

    @Override
    public AuthenticationExtensionsPaymentOutputs deserialize(JsonParser p, DeserializationContext ctxt) {
        ObjectNode node = (ObjectNode) p.readValueAsTree();
        JsonNode paymentNode = node.get(AuthenticationExtensionsPaymentOutputs.KEY_PAYMENT);
        if (paymentNode == null || paymentNode.isNull()) {
            return null;
        }

        BrowserBoundSignature browserBoundSignature = paymentNode.has("browserBoundSignature")
                ? ctxt.readTreeAsValue(paymentNode.get("browserBoundSignature"), BrowserBoundSignature.class)
                : null;

        return new AuthenticationExtensionsPaymentOutputs(browserBoundSignature);
    }
}
