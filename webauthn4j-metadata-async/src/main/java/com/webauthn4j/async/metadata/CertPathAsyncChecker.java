package com.webauthn4j.async.metadata;


import com.webauthn4j.metadata.CertPathCheckContext;
import com.webauthn4j.metadata.exception.MDSException;

import java.util.concurrent.CompletionStage;

public interface CertPathAsyncChecker {

    CompletionStage<Void> check(CertPathCheckContext context) throws MDSException;
}
