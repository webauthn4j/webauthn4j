/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webauthn4j.authenticator;

import com.webauthn4j.attestation.authenticator.WebAuthnAttestedCredentialData;
import com.webauthn4j.attestation.statement.WebAuthnAttestationStatement;
import com.webauthn4j.util.ConstUtil;

/**
 * A {@link WebAuthnAuthenticator} implementation
 */
public class WebAuthnAuthenticatorImpl implements WebAuthnAuthenticator {

    //~ Instance fields ================================================================================================
    private WebAuthnAttestedCredentialData attestationData;
    private WebAuthnAttestationStatement attestationStatement;
    private long counter;

    public WebAuthnAuthenticatorImpl(WebAuthnAttestedCredentialData attestationData, WebAuthnAttestationStatement attestationStatement, long counter) {
        this.attestationData = attestationData;
        this.attestationStatement = attestationStatement;
        setCounter(counter);
    }

    @Override
    public WebAuthnAttestedCredentialData getAttestedCredentialData() {
        return attestationData;
    }

    @Override
    public WebAuthnAttestationStatement getAttestationStatement() {
        return attestationStatement;
    }

    @Override
    public long getCounter() {
        return this.counter;
    }

    @Override
    public void setCounter(long value) {
        if(value > ConstUtil.UINT_MAX_VALUE){
            throw new IllegalArgumentException("[Assertion failed] - this argument is unsigned int. it must not exceed 4294967295.");
        }
        if(value < 0){
            throw new IllegalArgumentException("[Assertion failed] - this argument is unsigned int. it must not be negative value.");
        }
        this.counter = value;
    }

}
