/*
 * Copyright 2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webauthn4j.test;

import com.webauthn4j.data.client.Origin;
import com.webauthn4j.test.authenticator.AuthenticatorAdaptor;
import com.webauthn4j.test.authenticator.u2f.FIDOU2FAuthenticator;
import com.webauthn4j.test.authenticator.u2f.FIDOU2FAuthenticatorAdaptor;
import com.webauthn4j.test.authenticator.webauthn.*;
import com.webauthn4j.test.client.ClientPlatform;

public class EmulatorUtil {

    public static final PackedAuthenticator PACKED_AUTHENTICATOR = new PackedAuthenticator();
    public static final AndroidKeyAuthenticator ANDROID_KEY_AUTHENTICATOR = new AndroidKeyAuthenticator();
    public static final AndroidSafetyNetAuthenticator ANDROID_SAFETY_NET_AUTHENTICATOR = new AndroidSafetyNetAuthenticator();
    public static final TPMAuthenticator TPM_AUTHENTICATOR = new TPMAuthenticator();
    public static final FIDOU2FAuthenticator FIDO_U2F_AUTHENTICATOR = new FIDOU2FAuthenticator();
    public static final NoneAttestationAuthenticator NONE_ATTESTATION_AUTHENTICATOR = new NoneAttestationAuthenticator();

    private static final Origin origin = new Origin("http://example.com");

    private EmulatorUtil() {
    }

    public static ClientPlatform createClientPlatform(AuthenticatorAdaptor authenticatorAdaptor) {
        return new ClientPlatform(origin, authenticatorAdaptor);
    }

    public static ClientPlatform createClientPlatform(WebAuthnModelAuthenticator webAuthnModelAuthenticator) {
        WebAuthnAuthenticatorAdaptor webAuthnAuthenticatorAdaptor = new WebAuthnAuthenticatorAdaptor(webAuthnModelAuthenticator);
        return createClientPlatform(webAuthnAuthenticatorAdaptor);
    }

    public static ClientPlatform createClientPlatform(FIDOU2FAuthenticator fidoU2FAuthenticator) {
        FIDOU2FAuthenticatorAdaptor fidou2FAuthenticatorAdaptor = new FIDOU2FAuthenticatorAdaptor(fidoU2FAuthenticator);
        return createClientPlatform(fidou2FAuthenticatorAdaptor);
    }

    public static ClientPlatform createClientPlatform() {
        return createClientPlatform(new PackedAuthenticator());
    }
}
