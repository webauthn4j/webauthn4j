package net.sharplab.springframework.security.webauthn.client;

import net.sharplab.springframework.security.webauthn.attestation.authenticator.extension.Extension;
import net.sharplab.springframework.security.webauthn.client.challenge.Challenge;

import java.io.Serializable;
import java.util.HashMap;

/**
 * ClientData
 */
public class ClientData implements Serializable {

    //~ Instance fields ================================================================================================
    private String type;
    private Challenge challenge;
    private Origin origin;
    private String hashAlgorithm;
    private String tokenBinding;
    private HashMap<String, Extension> clientExtensions;
    private HashMap<String, Extension> authenticatorExtensions;


    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public Challenge getChallenge() {
        return challenge;
    }

    public void setChallenge(Challenge challenge) {
        this.challenge = challenge;
    }

    public Origin getOrigin() {
        return origin;
    }

    public void setOrigin(Origin origin) {
        this.origin = origin;
    }

    public String getHashAlgorithm() {
        return hashAlgorithm;
    }

    public void setHashAlgorithm(String hashAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
    }

    public String getTokenBinding() {
        return tokenBinding;
    }

    public void setTokenBinding(String tokenBinding) {
        this.tokenBinding = tokenBinding;
    }

    public HashMap<String, Extension> getClientExtensions() {
        return clientExtensions;
    }

    public void setClientExtensions(HashMap<String, Extension> clientExtensions) {
        this.clientExtensions = clientExtensions;
    }

    public HashMap<String, Extension> getAuthenticatorExtensions() {
        return authenticatorExtensions;
    }

    public void setAuthenticatorExtensions(HashMap<String, Extension> authenticatorExtensions) {
        this.authenticatorExtensions = authenticatorExtensions;
    }
}
