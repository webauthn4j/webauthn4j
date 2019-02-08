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

package com.webauthn4j.response.attestation.statement;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.webauthn4j.util.jws.JWS;
import com.webauthn4j.validator.exception.ConstraintViolationException;

import java.util.Objects;

@JsonIgnoreProperties(value = "format")
@JsonTypeName(AndroidSafetyNetAttestationStatement.FORMAT)
public class AndroidSafetyNetAttestationStatement implements CertificateBaseAttestationStatement {

    public static final String FORMAT = "android-safetynet";

    @JsonProperty
    private String ver;

    @JsonProperty
    private JWS<Response> response;

    @JsonCreator
    public AndroidSafetyNetAttestationStatement(
            @JsonProperty("ver") String ver,
            @JsonProperty("response") JWS<Response> response) {
        this.ver = ver;
        this.response = response;
    }

    @Override
    public String getFormat() {
        return FORMAT;
    }

    @Override
    public AttestationCertificatePath getX5c() {
        return getResponse().getHeader().getX5c();
    }

    @Override
    public void validate() {
        if (ver == null) {
            throw new ConstraintViolationException("ver must not be null");
        }
        if (response == null) {
            throw new ConstraintViolationException("response must not be null");
        }
    }

    public String getVer() {
        return ver;
    }

    public JWS<Response> getResponse() {
        return response;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AndroidSafetyNetAttestationStatement that = (AndroidSafetyNetAttestationStatement) o;
        return Objects.equals(ver, that.ver) &&
                Objects.equals(response, that.response);
    }

    @Override
    public int hashCode() {

        return Objects.hash(ver, response);
    }
}
