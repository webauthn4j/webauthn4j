package com.webauthn4j.spc.converter.jackson.serializer.json;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.util.Base64UrlUtil;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonGenerator;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.jsontype.TypeSerializer;
import tools.jackson.databind.ser.std.StdSerializer;

public class COSEKeyBase64UrlSerializer extends StdSerializer<COSEKey> {

    private final ObjectConverter objectConverter;

    public COSEKeyBase64UrlSerializer(@NotNull ObjectConverter objectConverter) {
        super(COSEKey.class);
        AssertUtil.notNull(objectConverter, "objectConverter must not be null");
        this.objectConverter = objectConverter;
    }

    @Override
    public void serialize(@NotNull COSEKey value, @NotNull JsonGenerator gen, @NotNull SerializationContext provider) {
        byte[] cborBytes = objectConverter.getCborMapper().writeValueAsBytes(value);
        gen.writeString(Base64UrlUtil.encodeToString(cborBytes));
    }

    @Override
    public void serializeWithType(@NotNull COSEKey value, @NotNull JsonGenerator gen, @NotNull SerializationContext ctxt, @NotNull TypeSerializer typeSer) {
        serialize(value, gen, ctxt);
    }
}
