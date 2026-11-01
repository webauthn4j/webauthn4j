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

package com.webauthn4j.appattest.verifier;

import com.webauthn4j.appattest.server.DCServerProperty;
import com.webauthn4j.verifier.exception.BadClientDataHashException;

import java.security.MessageDigest;

final class DCClientDataHashVerifier {

    private DCClientDataHashVerifier() {
    }

    static void verify(byte[] actual, DCServerProperty serverProperty) {
        byte[] expected = serverProperty.getClientDataHash();
        if (expected != null && !MessageDigest.isEqual(expected, actual)) {
            throw new BadClientDataHashException("clientDataHash does not match the server's expected value", expected, actual);
        }
    }
}
