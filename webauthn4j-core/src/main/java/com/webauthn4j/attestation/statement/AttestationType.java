package com.webauthn4j.attestation.statement;

public enum AttestationType {
    Basic,
    Self,
    AttCA, // RP cannot differentiate between Basic and Privacy CA from the attestation data.
    ECDAA,
    None
}
