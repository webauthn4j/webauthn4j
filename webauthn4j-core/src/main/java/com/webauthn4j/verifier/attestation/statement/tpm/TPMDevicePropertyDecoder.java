package com.webauthn4j.verifier.attestation.statement.tpm;

import com.webauthn4j.verifier.exception.BadAttestationStatementException;

public interface TPMDevicePropertyDecoder {

    TPMDeviceProperty decode(String subjectAlternativeName) throws BadAttestationStatementException;
}
