package com.webauthn4j.converter.jackson.serializer.cbor;

import com.webauthn4j.data.attestation.AttestationObject;

import java.util.Arrays;

public class AttestationObjectSerializer extends AbstractCtapCanonicalCborSerializer<AttestationObject> {

    public AttestationObjectSerializer() {
        super(AttestationObject.class, Arrays.asList(
                new FieldSerializationRule<>("fmt", AttestationObject::getFormat),
                new FieldSerializationRule<>("attStmt", AttestationObject::getAttestationStatement),
                new FieldSerializationRule<>("authData", AttestationObject::getAuthenticatorData)
        ));
    }
}
