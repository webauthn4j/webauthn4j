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

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.webauthn4j.util.WIP;
import com.webauthn4j.validator.exception.ConstraintViolationException;

@WIP
@JsonIgnoreProperties(value = "format")
@JsonTypeName(AndroidSafetyNetAttestationStatement.FORMAT)
public class AndroidSafetyNetAttestationStatement implements CertificateBaseAttestationStatement {

    public static final String FORMAT = "android-safetynet";

    @JsonProperty
    private String ver;

    @JsonProperty
    private JWS response;

    /**
     * Default constructor for Jackson deserialization
     */
    public AndroidSafetyNetAttestationStatement() {
        //nop
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

    public JWS getResponse() {
        return response;
    }

}
