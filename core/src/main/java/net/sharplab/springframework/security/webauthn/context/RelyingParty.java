package net.sharplab.springframework.security.webauthn.context;

import net.sharplab.springframework.security.webauthn.client.Origin;
import net.sharplab.springframework.security.webauthn.client.challenge.Challenge;

import java.io.Serializable;

/**
 * RelyingParty
 */
public class RelyingParty implements Serializable {

    private Origin origin;
    private String rpId;
    private Challenge challenge;

    public RelyingParty(Origin origin, String rpId, Challenge challenge) {
        this.origin = origin;
        this.rpId = rpId;
        this.challenge = challenge;
    }

    public Origin getOrigin() {
        return origin;
    }

    public String getRpId(){ return rpId; }

    public Challenge getChallenge() {
        return challenge;
    }

}
