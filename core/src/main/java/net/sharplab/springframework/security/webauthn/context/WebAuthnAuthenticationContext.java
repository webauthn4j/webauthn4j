package net.sharplab.springframework.security.webauthn.context;

import net.sharplab.springframework.security.webauthn.attestation.authenticator.WebAuthnAuthenticatorData;
import net.sharplab.springframework.security.webauthn.client.ClientData;
import org.springframework.security.core.Authentication;

import java.io.Serializable;

/**
 * WebAuthnAuthenticationContext
 */
public class WebAuthnAuthenticationContext implements Serializable {

    //~ Instance fields ================================================================================================

    private String credentialId;
    private byte[] rawClientData;
    private byte[] rawAuthenticatorData;
    private String clientDataJson;
    private ClientData clientData;
    private WebAuthnAuthenticatorData authenticatorData;
    private byte[] signature;
    private RelyingParty relyingParty;
    private Authentication currentAuthentication;


    public WebAuthnAuthenticationContext(String credentialId,
                                         byte[] rawClientData,
                                         byte[] rawAuthenticatorData,
                                         String clientDataJson,
                                         ClientData clientData,
                                         WebAuthnAuthenticatorData authenticatorData,
                                         byte[] signature,
                                         RelyingParty relyingParty,
                                         Authentication currentAuthentication) {
        this.credentialId = credentialId;
        this.rawClientData = rawClientData;
        this.rawAuthenticatorData = rawAuthenticatorData;
        this.clientDataJson = clientDataJson;
        this.clientData = clientData;
        this.authenticatorData = authenticatorData;
        this.signature = signature;
        this.relyingParty = relyingParty;
        this.currentAuthentication = currentAuthentication;
    }

    public String getCredentialId(){ return credentialId; }

    public byte[] getRawClientData() {
        return rawClientData;
    }

    public String getClientDataJson() {
        return clientDataJson;
    }

    public ClientData getClientData() {
        return clientData;
    }

    public byte[] getRawAuthenticatorData() {
        return rawAuthenticatorData;
    }

    public WebAuthnAuthenticatorData getAuthenticatorData() {
        return authenticatorData;
    }

    public byte[] getSignature() {
        return signature;
    }

    public RelyingParty getRelyingParty() {
        return relyingParty;
    }

    public Authentication getCurrentAuthentication() {
        return currentAuthentication;
    }

    public void setCurrentAuthentication(Authentication currentAuthentication) {
        this.currentAuthentication = currentAuthentication;
    }
}
