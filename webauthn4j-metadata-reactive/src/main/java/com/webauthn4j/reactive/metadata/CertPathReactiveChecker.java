package com.webauthn4j.reactive.metadata;


import com.webauthn4j.metadata.CertPathCheckContext;
import com.webauthn4j.metadata.exception.MDSException;

import java.util.concurrent.CompletionStage;

public interface CertPathReactiveChecker {

    CompletionStage<Void> check(CertPathCheckContext context) throws MDSException;
}
