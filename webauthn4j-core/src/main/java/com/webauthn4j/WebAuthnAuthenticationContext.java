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

package com.webauthn4j;

import java.nio.charset.StandardCharsets;


/**
 * WebAuthnAuthenticationContext
 */
public class WebAuthnAuthenticationContext {

    //~ Instance fields ================================================================================================

    // user inputs
    private String credentialId;
    private byte[] collectedClientData;
    private byte[] authenticatorData;
    private byte[] signature;

    // server property
    private RelyingParty relyingParty;


    public WebAuthnAuthenticationContext(String credentialId,
                                         byte[] collectedClientData,
                                         byte[] authenticatorData,
                                         byte[] signature,
                                         RelyingParty relyingParty) {
        this.credentialId = credentialId;
        this.collectedClientData = collectedClientData;
        this.authenticatorData = authenticatorData;
        this.signature = signature;
        this.relyingParty = relyingParty;
    }

    public String getCredentialId() {
        return credentialId;
    }

    public byte[] getCollectedClientData() {
        return collectedClientData;
    }

    public String getCollectedClientDataJson() {
        return new String(collectedClientData, StandardCharsets.UTF_8);
    }

    public byte[] getAuthenticatorData() {
        return authenticatorData;
    }

    public byte[] getSignature() {
        return signature;
    }

    public RelyingParty getRelyingParty() {
        return relyingParty;
    }
}
