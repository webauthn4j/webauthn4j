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

package com.webauthn4j.attestation;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.webauthn4j.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.attestation.statement.AttestationStatement;

import java.util.Objects;

public class AttestationObject {

    //~ Instance fields ================================================================================================
    @JsonProperty("authData")
    private AuthenticatorData authenticatorData;

    @JsonProperty("attStmt")
    @JsonTypeInfo(
            use = JsonTypeInfo.Id.NAME,
            include = JsonTypeInfo.As.EXTERNAL_PROPERTY,
            property = "fmt"
    )
    private AttestationStatement attestationStatement;

    public AttestationObject(AuthenticatorData authenticatorData, AttestationStatement attestationStatement) {
        this.authenticatorData = authenticatorData;
        this.attestationStatement = attestationStatement;
    }

    public AttestationObject() {
    }

    public com.webauthn4j.attestation.authenticator.AuthenticatorData getAuthenticatorData() {
        return authenticatorData;
    }

    @JsonProperty("fmt")
    public String getFormat() {
        return attestationStatement.getFormat();
    }

    public AttestationStatement getAttestationStatement() {
        return attestationStatement;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AttestationObject that = (AttestationObject) o;
        return Objects.equals(authenticatorData, that.authenticatorData) &&
                Objects.equals(attestationStatement, that.attestationStatement);
    }

    @Override
    public int hashCode() {
        return Objects.hash(authenticatorData, attestationStatement);
    }
}
