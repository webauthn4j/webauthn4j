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

package com.webauthn4j.appattest.data;

import com.webauthn4j.authenticator.CoreAuthenticator;
import com.webauthn4j.data.CoreAuthenticationParameters;
import com.webauthn4j.server.CoreServerProperty;

import java.util.List;

public class DCAssertionParameters extends CoreAuthenticationParameters {

    public DCAssertionParameters(CoreServerProperty serverProperty, CoreAuthenticator authenticator, boolean userVerificationRequired, boolean userPresenceRequired, List<String> expectedExtensionIds) {
        super(serverProperty, authenticator, userVerificationRequired, userPresenceRequired, expectedExtensionIds);
    }

    public DCAssertionParameters(CoreServerProperty serverProperty, CoreAuthenticator authenticator, boolean userVerificationRequired, boolean userPresenceRequired) {
        super(serverProperty, authenticator, userVerificationRequired, userPresenceRequired);
    }

    public DCAssertionParameters(CoreServerProperty serverProperty, CoreAuthenticator authenticator, boolean userVerificationRequired) {
        super(serverProperty, authenticator, userVerificationRequired);
    }
}
