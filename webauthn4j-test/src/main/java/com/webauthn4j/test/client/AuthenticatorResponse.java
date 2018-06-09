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

package com.webauthn4j.test.client;

public class AuthenticatorResponse {

    private byte[] clientDataJSON;
    private String clientExtensionsJSON;

    public AuthenticatorResponse(byte[] clientDataJSON, String clientExtensionsJSON) {
        this.clientDataJSON = clientDataJSON;
        this.clientExtensionsJSON = clientExtensionsJSON;
    }

    public AuthenticatorResponse(byte[] clientDataJSON) {
        this(clientDataJSON, null);
    }

    public byte[] getClientDataJSON() {
        return clientDataJSON;
    }

    public String getClientExtensionsJSON() {
        return clientExtensionsJSON;
    }
}
