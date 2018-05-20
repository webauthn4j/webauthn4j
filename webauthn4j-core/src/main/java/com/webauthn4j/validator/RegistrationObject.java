package com.webauthn4j.validator;

import com.webauthn4j.attestation.AttestationObject;
import com.webauthn4j.client.CollectedClientData;
import com.webauthn4j.server.ServerProperty;

public class RegistrationObject {
    private final CollectedClientData collectedClientData;
    private final byte[] collectedClientDataBytes;
    private final AttestationObject attestationObject;
    private final byte[] attestationObjectBytes;
    private final ServerProperty serverProperty;

    RegistrationObject(CollectedClientData collectedClientData,
                       byte[] collectedClientDataBytes,
                       AttestationObject attestationObject,
                       byte[] attestationObjectBytes,
                       ServerProperty serverProperty) {

        this.collectedClientData = collectedClientData;
        this.collectedClientDataBytes = collectedClientDataBytes;
        this.attestationObject = attestationObject;
        this.attestationObjectBytes = attestationObjectBytes;
        this.serverProperty = serverProperty;
    }

    public CollectedClientData getCollectedClientData() {
        return collectedClientData;
    }

    public byte[] getCollectedClientDataBytes() {
        return collectedClientDataBytes;
    }

    public AttestationObject getAttestationObject() {
        return attestationObject;
    }

    public byte[] getAttestationObjectBytes() {
        return attestationObjectBytes;
    }

    public ServerProperty getServerProperty() {
        return serverProperty;
    }

}
