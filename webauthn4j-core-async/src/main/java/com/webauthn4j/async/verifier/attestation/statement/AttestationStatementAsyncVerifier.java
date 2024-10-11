package com.webauthn4j.async.verifier.attestation.statement;

import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.data.attestation.statement.AttestationType;
import com.webauthn4j.verifier.CoreRegistrationObject;
import org.jetbrains.annotations.NotNull;

import java.util.concurrent.CompletionStage;

/**
 * Verifies the specified {@link AttestationStatement}
 */
public interface AttestationStatementAsyncVerifier {

    @NotNull
    CompletionStage<AttestationType> verify(@NotNull CoreRegistrationObject registrationObject);

    boolean supports(@NotNull CoreRegistrationObject registrationObject);

}
