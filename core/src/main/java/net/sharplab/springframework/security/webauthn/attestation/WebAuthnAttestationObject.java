package net.sharplab.springframework.security.webauthn.attestation;

import com.fasterxml.jackson.annotation.JsonProperty;
import net.sharplab.springframework.security.webauthn.attestation.authenticator.WebAuthnAuthenticatorData;
import net.sharplab.springframework.security.webauthn.attestation.statement.WebAuthnAttestationStatement;

import java.io.Serializable;

public class WebAuthnAttestationObject implements Serializable {

    //~ Instance fields ================================================================================================
    @JsonProperty("authData")
    private WebAuthnAuthenticatorData AuthenticatorData;
    @JsonProperty("fmt")
    private String format;
    @JsonProperty("attStmt")
    private WebAuthnAttestationStatement attestationStatement; //TODO: generalize


    public WebAuthnAuthenticatorData getAuthenticatorData() {
        return AuthenticatorData;
    }

    public void setAuthenticatorData(WebAuthnAuthenticatorData webAuthnAuthenticatorData) {
        this.AuthenticatorData = webAuthnAuthenticatorData;
    }

    public String getFormat() {
        return format;
    }

    public void setFormat(String format) {
        this.format = format;
    }

    public WebAuthnAttestationStatement getAttestationStatement() {
        return attestationStatement;
    }

    public void setAttestationStatement(WebAuthnAttestationStatement attestationStatement) {
        this.attestationStatement = attestationStatement;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof WebAuthnAttestationObject)) return false;

        WebAuthnAttestationObject that = (WebAuthnAttestationObject) o;

        if (AuthenticatorData != null ? !AuthenticatorData.equals(that.AuthenticatorData) : that.AuthenticatorData != null)
            return false;
        if (format != null ? !format.equals(that.format) : that.format != null) return false;
        return attestationStatement != null ? attestationStatement.equals(that.attestationStatement) : that.attestationStatement == null;
    }

    @Override
    public int hashCode() {
        int result = AuthenticatorData != null ? AuthenticatorData.hashCode() : 0;
        result = 31 * result + (format != null ? format.hashCode() : 0);
        result = 31 * result + (attestationStatement != null ? attestationStatement.hashCode() : 0);
        return result;
    }
}
