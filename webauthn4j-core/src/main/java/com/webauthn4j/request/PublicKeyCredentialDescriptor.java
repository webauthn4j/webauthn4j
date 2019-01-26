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

package com.webauthn4j.request;

import com.webauthn4j.util.WIP;

import java.io.Serializable;
import java.util.List;

@WIP
public class PublicKeyCredentialDescriptor implements Serializable {

    // ~ Instance fields
    // ================================================================================================

    private PublicKeyCredentialType type;
    private byte[] id;
    private List<AuthenticatorTransport> transports;

    public PublicKeyCredentialDescriptor(PublicKeyCredentialType type, byte[] id, List<AuthenticatorTransport> transports) {
        this.type = type;
        this.id = id;
        this.transports = transports;
    }

    public PublicKeyCredentialDescriptor() {
    }

    public PublicKeyCredentialType getType() {
        return type;
    }

    public byte[] getId() {
        return id;
    }

    public List<AuthenticatorTransport> getTransports() {
        return transports;
    }
}
