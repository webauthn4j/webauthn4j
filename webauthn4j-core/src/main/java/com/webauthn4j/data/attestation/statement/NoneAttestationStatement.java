/*
 * Copyright 2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webauthn4j.data.attestation.statement;

import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.webauthn4j.validator.exception.BadAttestationStatementException;
import org.checkerframework.checker.nullness.qual.NonNull;

import java.util.HashMap;
import java.util.Map;

@JsonIgnoreProperties(value = "format")
@JsonTypeName(NoneAttestationStatement.FORMAT)
public class NoneAttestationStatement implements AttestationStatement {

    public static final String FORMAT = "none";

    @JsonIgnore
    private final transient Map<String, Object> unknownProperties = new HashMap<>();

    @JsonIgnore
    @Override
    public @NonNull String getFormat() {
        return FORMAT;
    }

    @Override
    public void validate() {
        if (!unknownProperties.isEmpty()) {
            // This check is required by FIDO Conformance Tools
            throw new BadAttestationStatementException("Unknown property is set to the none attestation statement.");
        }
    }

    @JsonAnySetter
    private void addUnknownProperty(String name, Object value) {
        unknownProperties.put(name, value);
    }

    @Override
    public String toString() {
        return "NoneAttestationStatement()";
    }
}
