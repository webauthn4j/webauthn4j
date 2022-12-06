package com.webauthn4j.validator.attestation.statement.tpm;

import com.webauthn4j.validator.exception.BadAttestationStatementException;

public interface TPMDevicePropertyDecoder {

    TPMDeviceProperty decode(String subjectAlternativeName) throws BadAttestationStatementException;
}
