package com.webauthn4j.converter.jackson.serializer.cbor;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.jsontype.TypeSerializer;
import com.webauthn4j.data.attestation.authenticator.EdDSACOSEKey;
import org.checkerframework.checker.nullness.qual.NonNull;

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
    public void serializeWithType(@NonNull EdDSACOSEKey value, @NonNull JsonGenerator gen,
                                  @NonNull SerializerProvider provider, @NonNull TypeSerializer typeSer) throws IOException {
        super.serialize(value, gen, provider);
    }
}
