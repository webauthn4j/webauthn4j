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

package net.sharplab.springframework.security.webauthn.client;

import net.sharplab.springframework.security.webauthn.attestation.authenticator.extension.Extension;
import net.sharplab.springframework.security.webauthn.client.challenge.Challenge;

import java.io.Serializable;
import java.util.HashMap;

/**
 * ClientData
 */
public class ClientData implements Serializable {

    //~ Instance fields ================================================================================================
    private String type;
    private Challenge challenge;
    private Origin origin;
    private String hashAlgorithm;
    private String tokenBinding;
    private HashMap<String, Extension> clientExtensions;
    private HashMap<String, Extension> authenticatorExtensions;


    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public Challenge getChallenge() {
        return challenge;
    }

    public void setChallenge(Challenge challenge) {
        this.challenge = challenge;
    }

    public Origin getOrigin() {
        return origin;
    }

    public void setOrigin(Origin origin) {
        this.origin = origin;
    }

    public String getHashAlgorithm() {
        return hashAlgorithm;
    }

    public void setHashAlgorithm(String hashAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
    }

    public String getTokenBinding() {
        return tokenBinding;
    }

    public void setTokenBinding(String tokenBinding) {
        this.tokenBinding = tokenBinding;
    }

    public HashMap<String, Extension> getClientExtensions() {
        return clientExtensions;
    }

    public void setClientExtensions(HashMap<String, Extension> clientExtensions) {
        this.clientExtensions = clientExtensions;
    }

    public HashMap<String, Extension> getAuthenticatorExtensions() {
        return authenticatorExtensions;
    }

    public void setAuthenticatorExtensions(HashMap<String, Extension> authenticatorExtensions) {
        this.authenticatorExtensions = authenticatorExtensions;
    }
}
