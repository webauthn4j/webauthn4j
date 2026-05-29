package com.webauthn4j.spc.converter.jackson;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.spc.converter.jackson.deserializer.json.COSEKeyBase64UrlDeserializer;
import com.webauthn4j.spc.converter.jackson.deserializer.json.PaymentExtensionClientInputDeserializer;
import com.webauthn4j.spc.converter.jackson.deserializer.json.PaymentExtensionClientOutputDeserializer;
import com.webauthn4j.spc.converter.jackson.serializer.json.COSEKeyBase64UrlSerializer;
import com.webauthn4j.spc.data.client.CollectedClientPaymentData;
import com.webauthn4j.spc.data.extension.client.AuthenticationExtensionsPaymentInputs;
import com.webauthn4j.spc.data.extension.client.AuthenticationExtensionsPaymentOutputs;
import com.webauthn4j.util.AssertUtil;
import org.jetbrains.annotations.NotNull;
import tools.jackson.databind.module.SimpleModule;

public class SPCJSONModule extends SimpleModule {

    public SPCJSONModule(@NotNull ObjectConverter objectConverter) {
        super("SPCJSONModule");
        AssertUtil.notNull(objectConverter, "objectConverter must not be null");

        this.registerSubtypes(CollectedClientPaymentData.class);

        this.addDeserializer(AuthenticationExtensionsPaymentInputs.class,
                new PaymentExtensionClientInputDeserializer());
        this.addDeserializer(AuthenticationExtensionsPaymentOutputs.class,
                new PaymentExtensionClientOutputDeserializer());

        this.addDeserializer(COSEKey.class,
                new COSEKeyBase64UrlDeserializer(objectConverter));
        this.addSerializer(COSEKey.class,
                new COSEKeyBase64UrlSerializer(objectConverter));
    }
}
