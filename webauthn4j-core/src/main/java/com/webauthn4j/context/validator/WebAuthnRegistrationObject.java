package com.webauthn4j.context.validator;

import com.webauthn4j.attestation.WebAuthnAttestationObject;
import com.webauthn4j.client.CollectedClientData;
import com.webauthn4j.context.RelyingParty;

public class WebAuthnRegistrationObject {
    private CollectedClientData collectedClientData;
    private byte[] collectedClientDataBytes;
    private WebAuthnAttestationObject attestationObject;
    private byte[] attestationObjectBytes;
    private RelyingParty relyingParty;

    public WebAuthnRegistrationObject(CollectedClientData collectedClientData,
                                       byte[] collectedClientDataBytes,
                                       WebAuthnAttestationObject attestationObject,
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

    public WebAuthnAttestationObject getAttestationObject() {
        return attestationObject;
    }

    public byte[] getAttestationObjectBytes() {
        return attestationObjectBytes;
    }

    public RelyingParty getRelyingParty() {
        return relyingParty;
    }

}
