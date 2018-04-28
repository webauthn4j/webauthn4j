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

package com.webauthn4j.client;

import com.webauthn4j.attestation.authenticator.extension.Extension;
import com.webauthn4j.client.challenge.Challenge;

import java.io.Serializable;
import java.util.Map;

/**
 * CollectedClientData
 */
public class CollectedClientData implements Serializable {

    public static final String TYPE_WEBAUTHN_GET = "webauthn.get";
    public static final String TYPE_WEBAUTHN_CREATE = "webauthn.create";

    //~ Instance fields ================================================================================================
    private String type;
    private Challenge challenge;
    private Origin origin;
    private Object tokenBinding; // Since Firefox Nightly haven't conform latest WebAuthn spec as of 2018-03-17, made it Object type

    public CollectedClientData(String type,
                               Challenge challenge,
                               Origin origin,
                               Object tokenBinding) {
        this.type = type;
        this.challenge = challenge;
        this.origin = origin;
        this.tokenBinding = tokenBinding;
    }

    public CollectedClientData(){}

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

    public Object getTokenBinding() {
        return tokenBinding;
    }

    public void setTokenBinding(Object tokenBinding) {
        this.tokenBinding = tokenBinding;
    }

}
