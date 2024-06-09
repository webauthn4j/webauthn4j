package com.webauthn4j.async.verifier.attestation.trustworthiness.self;

import com.webauthn4j.test.TestAttestationStatementUtil;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatCode;


class NullSelfAttestationTrustworthinessAsyncVerifierTest {

    @Test
    void test(){
        NullSelfAttestationTrustworthinessAsyncVerifier target = new NullSelfAttestationTrustworthinessAsyncVerifier();
        assertThatCode(()-> target.verify(TestAttestationStatementUtil.createBasicPackedAttestationStatement()).toCompletableFuture().get()).doesNotThrowAnyException();
    }

}