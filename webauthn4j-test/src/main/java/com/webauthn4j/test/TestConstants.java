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

package com.webauthn4j.test;

import com.webauthn4j.data.attestation.statement.AttestationCertificatePath;
import com.webauthn4j.test.authenticator.u2f.FIDOU2FAuthenticator;
import com.webauthn4j.test.authenticator.webauthn.AndroidKeyAuthenticator;
import com.webauthn4j.test.authenticator.webauthn.AndroidSafetyNetAuthenticator;
import com.webauthn4j.test.authenticator.webauthn.PackedAuthenticator;
import com.webauthn4j.test.authenticator.webauthn.TPMAuthenticator;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class TestConstants {

    public static final PrivateKey GENERIC_2TIER_ATTESTATION_PRIVATE_KEY = TestAttestationUtil.load2tierTestAuthenticatorAttestationPrivateKey();

    public static final X509Certificate GENERIC_2TIER_ATTESTATION_CERTIFICATE = TestAttestationUtil.load2tierTestAuthenticatorAttestationCertificate();

    public static final PrivateKey GENERIC_3TIER_ATTESTATION_PRIVATE_KEY = TestAttestationUtil.load3tierTestAuthenticatorAttestationPrivateKey();

    public static final AttestationCertificatePath GENERIC_3TIER_ATTESTATION_CERTIFICATE_PATH = TestAttestationUtil.load3tierTestAttestationCertificatePath();

    public static final PackedAuthenticator PACKED_AUTHENTICATOR = new PackedAuthenticator();

    public static final AndroidKeyAuthenticator ANDROID_KEY_AUTHENTICATOR = new AndroidKeyAuthenticator();

    public static final AndroidSafetyNetAuthenticator ANDROID_SAFETY_NET_AUTHENTICATOR = new AndroidSafetyNetAuthenticator();

    public static final TPMAuthenticator TPM_AUTHENTICATOR = new TPMAuthenticator();

    public static final FIDOU2FAuthenticator FIDO_U2F_AUTHENTICATOR = new FIDOU2FAuthenticator();

}
