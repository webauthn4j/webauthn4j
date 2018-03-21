/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webauthn4j.webauthn.attestation;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.webauthn4j.webauthn.attestation.authenticator.WebAuthnAuthenticatorData;
import com.webauthn4j.webauthn.attestation.statement.WebAuthnAttestationStatement;

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
