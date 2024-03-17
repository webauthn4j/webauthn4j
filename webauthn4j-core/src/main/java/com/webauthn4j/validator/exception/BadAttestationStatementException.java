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

package com.webauthn4j.validator.exception;


import com.webauthn4j.data.attestation.statement.AttestationStatement;
import org.checkerframework.checker.nullness.qual.Nullable;

/**
 * Thrown if bad attestation statement is specified
 */
@SuppressWarnings("squid:S110")
public class BadAttestationStatementException extends ValidationException {

    private final AttestationStatement attestationStatement;

    public BadAttestationStatementException(@Nullable String message, @Nullable AttestationStatement attestationStatement, @Nullable Throwable cause) {
        super(message, cause);
        this.attestationStatement = attestationStatement;
    }

    public BadAttestationStatementException(@Nullable String message, @Nullable AttestationStatement attestationStatement) {
        super(message);
        this.attestationStatement = attestationStatement;
    }

    public BadAttestationStatementException(@Nullable String message, @Nullable Throwable cause) {
        super(message, cause);
        this.attestationStatement = null;
    }

    public BadAttestationStatementException(@Nullable String message) {
        super(message);
        this.attestationStatement = null;
    }

    public BadAttestationStatementException(@Nullable Throwable cause) {
        super(cause);
        this.attestationStatement = null;
    }

    public AttestationStatement getAttestationStatement() {
        return attestationStatement;
    }
}
