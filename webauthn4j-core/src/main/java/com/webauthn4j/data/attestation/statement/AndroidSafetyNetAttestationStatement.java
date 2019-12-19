/*
 * Copyright 2018 the original author or authors.
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

package com.webauthn4j.data.attestation.statement;

import com.fasterxml.jackson.annotation.*;
import com.webauthn4j.data.jws.JWS;
import com.webauthn4j.validator.exception.ConstraintViolationException;

import java.util.Objects;

@JsonTypeName(AndroidSafetyNetAttestationStatement.FORMAT)
public class AndroidSafetyNetAttestationStatement implements CertificateBaseAttestationStatement {

    public static final String FORMAT = "android-safetynet";

    private String ver;
    private JWS<Response> response;

    @JsonCreator
    public AndroidSafetyNetAttestationStatement(
            @JsonProperty("ver") String ver,
            @JsonProperty("response") JWS<Response> response) {
        this.ver = ver;
        this.response = response;
    }

    @JsonIgnore
    @Override
    public String getFormat() {
        return FORMAT;
    }

    @JsonIgnore
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

    @JsonGetter("ver")
    public String getVer() {
        return ver;
    }

    @JsonGetter("response")
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
