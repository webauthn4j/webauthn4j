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

package com.webauthn4j.async.verifier.attestation.trustworthiness.self;

import com.webauthn4j.data.attestation.statement.CertificateBaseAttestationStatement;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.util.CompletionStageUtil;
import com.webauthn4j.verifier.exception.BadAttestationStatementException;
import com.webauthn4j.verifier.exception.SelfAttestationProhibitedException;
import org.jetbrains.annotations.NotNull;

import java.util.concurrent.CompletionStage;

/**
 * Default implementation of {@link SelfAttestationTrustworthinessAsyncVerifier}
 */
public class DefaultSelfAttestationTrustworthinessAsyncVerifier implements SelfAttestationTrustworthinessAsyncVerifier {

    // ~ Instance fields
    // ================================================================================================

    private boolean isSelfAttestationAllowed = true;

    public CompletionStage<Void> verify(@NotNull CertificateBaseAttestationStatement attestationStatement) {
        return CompletionStageUtil.supply(()->{
            AssertUtil.notNull(attestationStatement, "attestationStatement must not be null");
            if (!isSelfAttestationAllowed()) {
                throw new SelfAttestationProhibitedException("SELF attestations is prohibited by configuration");
            }

            if (attestationStatement.getX5c() != null) {
                throw new BadAttestationStatementException("SELF attestation must not have x5c.");
            }
            return null;
        });
    }

    @SuppressWarnings("WeakerAccess")
    public boolean isSelfAttestationAllowed() {
        return this.isSelfAttestationAllowed;
    }

    public void setSelfAttestationAllowed(boolean selfAttestationAllowed) {
        this.isSelfAttestationAllowed = selfAttestationAllowed;
    }
}
