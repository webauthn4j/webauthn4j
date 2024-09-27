package com.webauthn4j.metadata;

import com.webauthn4j.metadata.exception.MDSException;


public interface CertPathChecker {

    void check(CertPathCheckContext context) throws MDSException;
}
