package com.webauthn4j.test;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class TestData {

    public static final PrivateKey FIDO_U2F_AUTHENTICATOR_PRIVATE_KEY = TestUtil.load2tierTestAuthenticatorAttestationPrivateKey();

    public static final X509Certificate FIDO_U2F_AUTHENTICATOR_ATTESTATION_CERTIFICATE = TestUtil.load2tierTestAuthenticatorAttestationCertificate();
}
