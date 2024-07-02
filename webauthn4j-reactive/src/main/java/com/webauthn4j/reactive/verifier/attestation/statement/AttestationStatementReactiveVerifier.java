package com.webauthn4j.reactive.verifier.attestation.statement;

import com.webauthn4j.data.attestation.statement.AttestationType;
import com.webauthn4j.verifier.CoreRegistrationObject;
import com.webauthn4j.verifier.attestation.statement.AttestationStatementVerifier;
import org.jetbrains.annotations.NotNull;

import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;

public interface AttestationStatementReactiveVerifier {

    @NotNull
    CompletionStage<AttestationType> verify(@NotNull CoreRegistrationObject registrationObject);

    boolean supports(@NotNull CoreRegistrationObject registrationObject);

}
