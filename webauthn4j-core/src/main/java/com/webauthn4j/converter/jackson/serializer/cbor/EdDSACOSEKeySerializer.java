package com.webauthn4j.converter.jackson.serializer.cbor;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.jsontype.TypeSerializer;
import com.webauthn4j.data.attestation.authenticator.EdDSACOSEKey;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.util.Arrays;

public class EdDSACOSEKeySerializer extends AbstractCtapCanonicalCborSerializer<EdDSACOSEKey>{

    public EdDSACOSEKeySerializer() {
        super(EdDSACOSEKey.class, Arrays.asList(
                new FieldSerializationRule<>(1, EdDSACOSEKey::getKeyType),
                new FieldSerializationRule<>(2, EdDSACOSEKey::getKeyId),
                new FieldSerializationRule<>(3, EdDSACOSEKey::getAlgorithm),
                new FieldSerializationRule<>(4, EdDSACOSEKey::getKeyOps),
                new FieldSerializationRule<>(5, EdDSACOSEKey::getBaseIV),
                new FieldSerializationRule<>(-1, EdDSACOSEKey::getCurve),
                new FieldSerializationRule<>(-2, EdDSACOSEKey::getX),
                new FieldSerializationRule<>(-4, EdDSACOSEKey::getD)
        ));
    }

    @Override
    public void serializeWithType(@NotNull EdDSACOSEKey value, @NotNull JsonGenerator gen,
                                  @NotNull SerializerProvider provider, @NotNull TypeSerializer typeSer) throws IOException {
        super.serialize(value, gen, provider);
    }
}
