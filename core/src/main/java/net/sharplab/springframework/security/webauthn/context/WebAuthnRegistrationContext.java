package net.sharplab.springframework.security.webauthn.context;

import net.sharplab.springframework.security.webauthn.attestation.WebAuthnAttestationObject;
import net.sharplab.springframework.security.webauthn.client.ClientData;

/**
 * WebAuthnRegistrationContext
 */
public class WebAuthnRegistrationContext {

    private ClientData clientData;
    private byte[] clientDataBytes;
    private WebAuthnAttestationObject attestationObject;
    private byte[] attestationObjectBytes;
    private RelyingParty relyingParty;

    public WebAuthnRegistrationContext(ClientData clientData,
                                byte[] clientDataBytes,
                                WebAuthnAttestationObject attestationObject,
                                byte[] attestationObjectBytes,
                                RelyingParty relyingParty){

        this.clientData = clientData;
        this.clientDataBytes = clientDataBytes;
        this.attestationObject = attestationObject;
        this.attestationObjectBytes = attestationObjectBytes;
        this.relyingParty = relyingParty;
    }

    public ClientData getClientData() {
        return clientData;
    }

    public byte[] getClientDataBytes() {
        return clientDataBytes;
    }

    public WebAuthnAttestationObject getAttestationObject() {
        return attestationObject;
    }

    public byte[] getAttestationObjectBytes() {
        return attestationObjectBytes;
    }

    public RelyingParty getRelyingParty(){ return relyingParty;}
}
