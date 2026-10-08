package com.webauthn4j.converter.jackson.serializer.cbor;

import com.webauthn4j.data.attestation.authenticator.AKPCOSEKey;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonGenerator;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.jsontype.TypeSerializer;

import java.util.Arrays;

public class AKPCOSEKeySerializer extends AbstractCtapCanonicalCborSerializer<AKPCOSEKey> {

    public AKPCOSEKeySerializer() {
        super(AKPCOSEKey.class, Arrays.asList(
                new FieldSerializationRule<>(1, AKPCOSEKey::getKeyType),
                new FieldSerializationRule<>(2, AKPCOSEKey::getKeyId),
                new FieldSerializationRule<>(3, AKPCOSEKey::getAlgorithm),
                new FieldSerializationRule<>(4, AKPCOSEKey::getKeyOps),
                new FieldSerializationRule<>(5, AKPCOSEKey::getBaseIV),
                new FieldSerializationRule<>(-1, AKPCOSEKey::getPub),
                new FieldSerializationRule<>(-2, AKPCOSEKey::getPriv)
        ));
    }

    @Override
    public void serializeWithType(@NotNull AKPCOSEKey value, @NotNull JsonGenerator gen,
                                  @NotNull SerializationContext provider, @NotNull TypeSerializer typeSer) {
        super.serialize(value, gen, provider);
    }
}
