package com.webauthn4j.test;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class CoreTestData {

    public static final PrivateKey AUTHENTICATOR_PRIVATE_KEY = CoreTestUtil.loadPrivateKeyFromClassPath("/attestation/private/ssw-test-authenticator.key");

    public static final X509Certificate AUTHENTICATOR_ATTESTATION_CERTIFICATE = CoreTestUtil.loadTestAuthenticatorCertificate();
}
