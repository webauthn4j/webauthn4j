package com.webauthn4j.validator;

import com.webauthn4j.rp.RelyingParty;
import com.webauthn4j.attestation.AttestationObject;
import com.webauthn4j.client.CollectedClientData;

public class RegistrationObject {
    private CollectedClientData collectedClientData;
    private byte[] collectedClientDataBytes;
    private AttestationObject attestationObject;
    private byte[] attestationObjectBytes;
    private RelyingParty relyingParty;

    RegistrationObject(CollectedClientData collectedClientData,
                       byte[] collectedClientDataBytes,
                       AttestationObject attestationObject,
                       byte[] attestationObjectBytes,
                       RelyingParty relyingParty) {

        this.collectedClientData = collectedClientData;
        this.collectedClientDataBytes = collectedClientDataBytes;
        this.attestationObject = attestationObject;
        this.attestationObjectBytes = attestationObjectBytes;
        this.relyingParty = relyingParty;
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

    public RelyingParty getRelyingParty() {
        return relyingParty;
    }

}
