package com.webauthn4j.converter.jackson.serializer.cbor;

import com.webauthn4j.data.attestation.statement.CompoundAttestationStatementItem;

import java.util.Arrays;

public class CompoundAttestationStatementItemSerializer extends AbstractCtapCanonicalCborSerializer<CompoundAttestationStatementItem> {

    public CompoundAttestationStatementItemSerializer() {
        super(CompoundAttestationStatementItem.class, Arrays.asList(
                new FieldSerializationRule<>("fmt", CompoundAttestationStatementItem::getFormat),
                new FieldSerializationRule<>("attStmt", CompoundAttestationStatementItem::getAttestationStatement)
        ));
    }
}
