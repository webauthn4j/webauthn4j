package net.sharplab.springframework.security.webauthn.sample.domain.model;

import com.webauthn4j.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.attestation.statement.AttestationStatement;
import lombok.Data;


/**
 * Authenticator
 */
@Data
public class Authenticator implements com.webauthn4j.authenticator.Authenticator {

    //~ Instance fields ================================================================================================
    private Integer id;
    private String name;

    private byte[] rpIdHash;
    private long counter;
    private AttestedCredentialData attestedCredentialData;
    private AttestationStatement attestationStatement;

    /**
     * Constructor
     */
    public Authenticator() {
        //nop
    }

    /**
     * Constructor
     *
     * @param name authenticator's friendly name
     */
    public Authenticator(String name) {
        this.setName(name);
    }

}
