package com.webauthn4j.async.verifier.attestation.trustworthiness.self;

import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.attestation.statement.PackedAttestationStatement;
import com.webauthn4j.test.TestAttestationStatementUtil;
import com.webauthn4j.verifier.exception.BadAttestationStatementException;
import com.webauthn4j.verifier.exception.SelfAttestationProhibitedException;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DefaultSelfAttestationTrustworthinessAsyncVerifierTest {

    @Test
    void verify_test() {
        DefaultSelfAttestationTrustworthinessAsyncVerifier target = new DefaultSelfAttestationTrustworthinessAsyncVerifier();
        PackedAttestationStatement attestationStatement = TestAttestationStatementUtil.createSelfPackedAttestationStatement(COSEAlgorithmIdentifier.ES256, new byte[32]);

        assertThatCode(()-> target.verify(attestationStatement).toCompletableFuture().get()).doesNotThrowAnyException();
    }

    @Test
    void verify_basic_type_attestation_statement_test() {
        DefaultSelfAttestationTrustworthinessAsyncVerifier target = new DefaultSelfAttestationTrustworthinessAsyncVerifier();
        PackedAttestationStatement attestationStatement = TestAttestationStatementUtil.createBasicPackedAttestationStatement();

        assertThatThrownBy(() -> target.verify(attestationStatement).toCompletableFuture().get()).getRootCause().isInstanceOf(BadAttestationStatementException.class);
    }

    @Test
    void verify_test_with_self_attestation_allowed_false() {
        DefaultSelfAttestationTrustworthinessAsyncVerifier target = new DefaultSelfAttestationTrustworthinessAsyncVerifier(false);
        PackedAttestationStatement attestationStatement = TestAttestationStatementUtil.createSelfPackedAttestationStatement(COSEAlgorithmIdentifier.ES256, new byte[32]);

        assertThatThrownBy(() -> target.verify(attestationStatement).toCompletableFuture().get()).getRootCause().isInstanceOf(SelfAttestationProhibitedException.class);
    }

}