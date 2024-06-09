package com.webauthn4j.reactive.verifier.attestation.statement.internal;

import com.webauthn4j.data.attestation.statement.AttestationType;
import com.webauthn4j.reactive.verifier.attestation.statement.AttestationStatementReactiveVerifier;
import com.webauthn4j.util.CompletionStageUtil;
import com.webauthn4j.verifier.CoreRegistrationObject;
import com.webauthn4j.verifier.attestation.statement.AttestationStatementVerifier;
import org.jetbrains.annotations.NotNull;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

public abstract class AttestationStatementVerifierDelegate implements AttestationStatementReactiveVerifier {

    protected final AttestationStatementVerifier attestationStatementVerifier;

    public AttestationStatementVerifierDelegate(AttestationStatementVerifier attestationStatementVerifier){
        this.attestationStatementVerifier = attestationStatementVerifier;
    }


    @Override
    public @NotNull CompletionStage<AttestationType> verify(@NotNull CoreRegistrationObject registrationObject) {
        return CompletionStageUtil.supply(()-> attestationStatementVerifier.verify(registrationObject));
    }

    @Override
    public boolean supports(@NotNull CoreRegistrationObject registrationObject) {
        return attestationStatementVerifier.supports(registrationObject);
    }
}
