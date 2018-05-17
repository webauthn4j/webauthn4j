package com.webauthn4j.attestation.statement;

public enum AttestationType {
    BASIC,
    SELF,
    ATT_CA, // RP cannot differentiate between BASIC and Privacy CA from the attestation data.
    ECDAA,
    NONE
}
