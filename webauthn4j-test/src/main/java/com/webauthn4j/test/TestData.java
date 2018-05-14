package com.webauthn4j.test;

import java.security.PrivateKey;
import java.security.cert.CertPath;
import java.security.cert.X509Certificate;

public class TestData {

    public static final PrivateKey FIDO_U2F_AUTHENTICATOR_ATTESTATION_PRIVATE_KEY = TestUtil.load2tierTestAuthenticatorAttestationPrivateKey();

    public static final X509Certificate FIDO_U2F_AUTHENTICATOR_ATTESTATION_CERTIFICATE = TestUtil.load2tierTestAuthenticatorAttestationCertificate();

    public static final PrivateKey USER_VERIFYING_AUTHENTICATOR_ATTESTATION_PRIVATE_KEY = TestUtil.load3tierTestAuthenticatorAttestationPrivateKey();

    public static final CertPath USER_VERIFYING_AUTHENTICATOR_ATTESTATION_CERT_PATH = TestUtil.load3tierTestCertPath();
}
