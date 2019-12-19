/*
 * Copyright 2018 the original author or authors.
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

package com.webauthn4j.test.authenticator.u2f;

import com.webauthn4j.util.WIP;

@WIP
public class AuthenticationResponse {

    private byte userPresence;
    private byte[] counter;
    private byte[] signature;

    public AuthenticationResponse(byte userPresence, byte[] counter, byte[] signature) {
        if (counter.length != 4) {
            throw new IllegalArgumentException("counter must be 4 bytes");
        }

        this.userPresence = userPresence;
        this.counter = counter;
        this.signature = signature;
    }

    public byte getUserPresence() {
        return userPresence;
    }

    public byte[] getCounter() {
        return counter;
    }

    public byte[] getSignature() {
        return signature;
    }
}
