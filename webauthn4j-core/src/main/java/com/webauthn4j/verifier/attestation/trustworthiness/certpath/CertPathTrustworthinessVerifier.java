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

package com.webauthn4j.verifier.attestation.trustworthiness.certpath;

import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.data.attestation.statement.CertificateBaseAttestationStatement;
import org.jetbrains.annotations.NotNull;

import java.time.Instant;

/**
 * Verifies the specified {@link AttestationStatement} x5c trustworthiness
 */
public interface CertPathTrustworthinessVerifier {

    void verify(@NotNull AAGUID aaguid, @NotNull CertificateBaseAttestationStatement attestationStatement, @NotNull Instant timestamp);

    default void verify(@NotNull AAGUID aaguid, @NotNull CertificateBaseAttestationStatement attestationStatement) {
        verify(aaguid, attestationStatement, Instant.now());
    }
}
