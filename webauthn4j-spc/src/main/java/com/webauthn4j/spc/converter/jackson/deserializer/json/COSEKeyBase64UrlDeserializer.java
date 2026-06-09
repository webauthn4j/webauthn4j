package com.webauthn4j.spc.converter.jackson.deserializer.json;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.util.Base64UrlUtil;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.jsontype.TypeDeserializer;
import tools.jackson.databind.deser.std.StdDeserializer;

public class COSEKeyBase64UrlDeserializer extends StdDeserializer<COSEKey> {

    private final ObjectConverter objectConverter;

    public COSEKeyBase64UrlDeserializer(@NotNull ObjectConverter objectConverter) {
        super(COSEKey.class);
        AssertUtil.notNull(objectConverter, "objectConverter must not be null");
        this.objectConverter = objectConverter;
    }

    @Override
    public COSEKey deserialize(@NotNull JsonParser p, @NotNull DeserializationContext ctxt) {
        String base64UrlString = p.getValueAsString();
        if (base64UrlString == null) {
            return null;
        }
        byte[] cborBytes = Base64UrlUtil.decode(base64UrlString);
        return objectConverter.getCborMapper().readValue(cborBytes, COSEKey.class);
    }

    @Override
    public Object deserializeWithType(@NotNull JsonParser p, @NotNull DeserializationContext ctxt, @NotNull TypeDeserializer typeDeserializer) {
        return deserialize(p, ctxt);
    }
}
