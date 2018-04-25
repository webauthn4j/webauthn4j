package com.webauthn4j.test;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class TestData {

    public static final PrivateKey AUTHENTICATOR_PRIVATE_KEY = TestUtil.loadTestAuthenticatorAttestationPrivateKey();

    public static final X509Certificate AUTHENTICATOR_ATTESTATION_CERTIFICATE = TestUtil.loadTestAuthenticatorAttestationCertificate();
}
