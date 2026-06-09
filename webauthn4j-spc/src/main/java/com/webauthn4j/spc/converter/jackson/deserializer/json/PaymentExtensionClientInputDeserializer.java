package com.webauthn4j.spc.converter.jackson.deserializer.json;

import com.webauthn4j.converter.jackson.deserializer.json.ExtensionClientInputDeserializer;
import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.spc.data.client.PaymentCredentialInstrument;
import com.webauthn4j.spc.data.client.PaymentCurrencyAmount;
import com.webauthn4j.spc.data.client.PaymentEntityLogo;
import com.webauthn4j.spc.data.extension.client.AuthenticationExtensionsPaymentInputs;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

import java.util.List;
import java.util.Set;

public class PaymentExtensionClientInputDeserializer
        extends ExtensionClientInputDeserializer<AuthenticationExtensionsPaymentInputs> {

    public PaymentExtensionClientInputDeserializer() {
        super(AuthenticationExtensionsPaymentInputs.class);
    }

    @Override
    public @NotNull Set<String> getKeys() {
        return Set.of(AuthenticationExtensionsPaymentInputs.KEY_PAYMENT);
    }

    @Override
    public AuthenticationExtensionsPaymentInputs deserialize(JsonParser p, DeserializationContext ctxt) {
        ObjectNode node = (ObjectNode) p.readValueAsTree();
        JsonNode paymentNode = node.get(AuthenticationExtensionsPaymentInputs.KEY_PAYMENT);
        if (paymentNode == null || paymentNode.isNull()) {
            return null;
        }

        Boolean isPayment = paymentNode.has("isPayment") ? paymentNode.get("isPayment").asBoolean() : null;

        List<PublicKeyCredentialParameters> browserBoundPubKeyCredParams = paymentNode.has("browserBoundPubKeyCredParams")
                ? ctxt.readTreeAsValue(paymentNode.get("browserBoundPubKeyCredParams"),
                    ctxt.getTypeFactory().constructCollectionType(List.class, PublicKeyCredentialParameters.class))
                : null;

        String rpId = paymentNode.has("rpId") ? paymentNode.get("rpId").stringValue() : null;
        Origin topOrigin = paymentNode.has("topOrigin") ? new Origin(paymentNode.get("topOrigin").stringValue()) : null;
        String payeeName = paymentNode.has("payeeName") ? paymentNode.get("payeeName").stringValue() : null;
        Origin payeeOrigin = paymentNode.has("payeeOrigin") ? new Origin(paymentNode.get("payeeOrigin").stringValue()) : null;

        List<PaymentEntityLogo> paymentEntitiesLogos = paymentNode.has("paymentEntitiesLogos")
                ? ctxt.readTreeAsValue(paymentNode.get("paymentEntitiesLogos"),
                    ctxt.getTypeFactory().constructCollectionType(List.class, PaymentEntityLogo.class))
                : null;

        PaymentCurrencyAmount total = paymentNode.has("total")
                ? ctxt.readTreeAsValue(paymentNode.get("total"), PaymentCurrencyAmount.class)
                : null;

        PaymentCredentialInstrument instrument = paymentNode.has("instrument")
                ? ctxt.readTreeAsValue(paymentNode.get("instrument"), PaymentCredentialInstrument.class)
                : null;

        return new AuthenticationExtensionsPaymentInputs(
                isPayment, browserBoundPubKeyCredParams, rpId, topOrigin,
                payeeName, payeeOrigin, paymentEntitiesLogos, total, instrument);
    }
}
