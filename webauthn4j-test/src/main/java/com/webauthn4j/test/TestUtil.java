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

import com.webauthn4j.anchor.TrustAnchorProvider;
import com.webauthn4j.attestation.AttestationObject;
import com.webauthn4j.attestation.authenticator.*;
import com.webauthn4j.attestation.statement.*;
import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.authenticator.AuthenticatorImpl;
import com.webauthn4j.client.ClientDataType;
import com.webauthn4j.client.CollectedClientData;
import com.webauthn4j.client.Origin;
import com.webauthn4j.client.challenge.Challenge;
import com.webauthn4j.client.challenge.DefaultChallenge;
import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.Base64UrlUtil;
import com.webauthn4j.util.CertificateUtil;
import com.webauthn4j.util.KeyUtil;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.util.StreamUtils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.*;

import static com.webauthn4j.attestation.authenticator.AuthenticatorData.BIT_AT;
import static com.webauthn4j.attestation.authenticator.AuthenticatorData.BIT_UP;

/**
 * A utility class for core module test
 */
public class TestUtil {

    private TestUtil() {
    }

    public static AttestationObject createAttestationObjectWithFIDOU2FAttestationStatement() {
        return new AttestationObject(createAuthenticatorData(), createFIDOU2FAttestationStatement());
    }

    public static AuthenticatorData createAuthenticatorData() {
        byte flags = BIT_UP | BIT_AT;
        return new AuthenticatorData(new byte[32], flags, 1, createAttestedCredentialData());
    }

    public static AttestedCredentialData createAttestedCredentialData() {
        return new AttestedCredentialData(new byte[16], new byte[32], createECCredentialPublicKey());
    }

    public static ECCredentialPublicKey createECCredentialPublicKey() {
        return new ECCredentialPublicKey(
                COSEKeyType.EC2,
                null,
                COSEAlgorithmIdentifier.ES256,
                null,
                null,
                Curve.SECP256R1,
                new byte[32],
                new byte[32]
        );
    }

    public static RSACredentialPublicKey createRSCredentialPublicKey() {
        RSACredentialPublicKey credentialPublicKey;
        credentialPublicKey = new RSACredentialPublicKey(
                COSEKeyType.RSA,
                null,
                COSEAlgorithmIdentifier.RS256,
                null,
                null,
                new byte[32],
                new byte[32]
        );
        return credentialPublicKey;
    }

    public static FIDOU2FAttestationStatement createFIDOU2FAttestationStatement() {
        return createFIDOU2FAttestationStatement(create2tierTestAuthenticatorCertPath());
    }

    public static FIDOU2FAttestationStatement createFIDOU2FAttestationStatement(AttestationCertificatePath certPath) {

        byte[] sig = new byte[32];

        return new FIDOU2FAttestationStatement(certPath, sig);
    }

    public static PackedAttestationStatement createBasicPackedAttestationStatement() {
        byte[] sig = new byte[32];
        AttestationCertificatePath certPath = load3tierTestCertPath();
        return new PackedAttestationStatement(COSEAlgorithmIdentifier.ES256, sig, certPath, null);
    }

    public static AttestationCertificatePath create2tierTestAuthenticatorCertPath() {
        return new AttestationCertificatePath(Collections.singletonList(TestUtil.load2tierTestAuthenticatorAttestationCertificate()));
    }

    public static AttestationCertificatePath load3tierTestCertPath() {
        return new AttestationCertificatePath(Arrays.asList(load3tierTestAuthenticatorAttestationCertificate(), load3tierTestIntermediateCACertificate()));
    }

    public static X509Certificate load3tierTestRootCACertificate() {
        return loadCertificateFromClassPath("/attestation/3tier/certs/3tier-test-root-CA.crt");
    }

    public static X509Certificate load3tierTestIntermediateCACertificate() {
        return loadCertificateFromClassPath("/attestation/3tier/certs/3tier-test-intermediate-CA.crt");
    }

    public static X509Certificate load3tierTestAuthenticatorAttestationCertificate() {
        return loadCertificateFromClassPath("/attestation/3tier/certs/3tier-test-authenticator.crt");
    }

    public static X509Certificate load2tierTestRootCACertificate() {
        return loadCertificateFromClassPath("/attestation/2tier/certs/2tier-test-root-CA.crt");
    }

    public static X509Certificate load2tierTestAuthenticatorAttestationCertificate() {
        return loadCertificateFromClassPath("/attestation/2tier/certs/2tier-test-authenticator.crt");
    }


    public static X509Certificate loadCertificateFromClassPath(String classPath) {
        ClassPathResource resource = new ClassPathResource(classPath);
        try {
            return CertificateUtil.generateX509Certificate(resource.getInputStream());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public static X509Certificate loadFirefoxSWTokenAttestationCertificate() {
        String base64Certificate = "MIIBMTCB2KADAgECAgRdWm5nMAoGCCqGSM49BAMCMCExHzAdBgNVBAMTFkZpcmVmb3ggVTJGIFNvZnQgVG9rZW4wHhcNMTcwODE5MTExMDI3WhcNMTcwODIxMTExMDI3WjAhMR8wHQYDVQQDExZGaXJlZm94IFUyRiBTb2Z0IFRva2VuMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmNdtc7TW47xJcunwo_5ZuqSeHKJDZixC3AhTy2OEnYZfLmLZn9ssfWqLmPY4E642bKRDsm6qLNfjj_z9ufejNTAKBggqhkjOPQQDAgNIADBFAiEA6SdHwFyOq1trbQA6TLxLHS11EYUYDWyA24BnsJD8TrACIEw7k4aGBMOYlT5uMXLlj4bV5jo1Svi83VOpBo5ykMvd";
        return createCertificate(base64Certificate);
    }

    public static X509Certificate loadFeitianU2FTokenAttestationCertificate() {
        String base64Certificate = "MIIBTDCB86ADAgECAgrMFgqn4TlPa3dQMAoGCCqGSM49BAMCMBcxFTATBgNVBAMTDEZUIEZJRE8gMDEwMDAeFw0xNjA0MTUxNDUwMzJaFw0yNjA0MTUxNDUwMzJaMCcxJTAjBgNVBAMTHEZUIEZJRE8gVTJGIDExNjE2MTczMDMwNTAyMTAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATG1tXh9HyGi4UJapsP3Fw8NEwRr5WEYfV5xOvP2XU4jpnJ17SEbyZTCn7rX38Ept32BPr6IaOmamqAdQvsDpNgoxcwFTATBgsrBgEEAYLlHAIBAQQEAwIEMDAKBggqhkjOPQQDAgNIADBFAiEA3wPvLOvjpbU3VCsKBjWtb5MzcX_I2p7NN_X03kyyFoUCIAxoJPinKGUxoNR_bhx3uZHtQQpwLWuaBND9y2Omhf47";
        return createCertificate(base64Certificate);
    }

    public static X509Certificate loadYubikeyAttestationCertificate() {
        String base64Certificate = "MIICRDCCAS6gAwIBAgIEeMDfDjALBgkqhkiG9w0BAQswLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcyMDA2MzEwIBcNMTQwODAxMDAwMDAwWhgPMjA1MDA5MDQwMDAwMDBaMCoxKDAmBgNVBAMMH1l1YmljbyBVMkYgRUUgU2VyaWFsIDIwMjU5MDU5MzQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS1uHFcg_3-DqFcRXeshY30jBdv3oedyvS4PUDTIPJvreYl_Pf1yK_YNRj4254h7Ag7GEWAxxfsSkcLlopvuj9vozswOTAiBgkrBgEEAYLECgIEFTEuMy42LjEuNC4xLjQxNDgyLjEuMTATBgsrBgEEAYLlHAIBAQQEAwIFIDALBgkqhkiG9w0BAQsDggEBAD72q_ZKkWsL-ZSTjdyVNOBUQAJoVninLEOnq-ZdkGX_YfRRzoo67thmidGQuVCvAHpU0THu8G_ia06nuz4yt5IFpd-nYAQ0U-NK-ETDfNSoX4xcLYcOCiiyt-1EAkH9s3krIHaw4Yr6m0Mu7vwmWLoJBcQbJKk8bsi7ptVvM-jWU9fPa9UBVFWiZZdA99zFHMAxYJzQPqbN6Tmeygh2MpB2P7TI0A9WkGmhJUkAauuwaiGiFOSZmDe0KegdflbTOlSS3ToWHIKTlUCBqn7vdJw6Vj2919ujlcxHPkRpbUGRhcJDesg6wGTBy-RyJ_96G3fH1eoMNn1F9jC9mY1Zsm4=";
        return createCertificate(base64Certificate);
    }

    public static X509Certificate createCertificate(String base64Certificate) {
        try {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(Base64UrlUtil.decode(base64Certificate)));
        } catch (CertificateException e) {
            throw new IllegalStateException(e);
        }
    }

    public static CollectedClientData createClientData(ClientDataType type) {
        return new CollectedClientData(type, createChallenge(), createOrigin(), null);
    }

    public static byte[] createClientDataJSON(ClientDataType type) {
        return new CollectedClientDataConverter().convertToBytes(createClientData(type));
    }

    public static Challenge createChallenge() {
        UUID uuid = UUID.randomUUID();
        long hi = uuid.getMostSignificantBits();
        long lo = uuid.getLeastSignificantBits();
        byte[] challengeValue = ByteBuffer.allocate(16).putLong(hi).putLong(lo).array();
        return new DefaultChallenge(challengeValue);
    }

    public static Origin createOrigin() {
        return new Origin("https://localhost:8080");
    }

    public static ServerProperty createRelyingParty() {
        return new ServerProperty(createOrigin(), "localhost", createChallenge(), null);
    }

    public static PrivateKey load3tierTestAuthenticatorAttestationPrivateKey() {
        return loadPrivateKey("classpath:attestation/3tier/private/3tier-test-authenticator.der");
    }

    public static PrivateKey load2tierTestAuthenticatorAttestationPrivateKey() {
        return loadPrivateKey("classpath:attestation/2tier/private/2tier-test-authenticator.der");
    }

    public static PrivateKey loadPrivateKeyFromResource(Resource resource) {
        try {
            InputStream inputStream = resource.getInputStream();
            byte[] data = StreamUtils.copyToByteArray(inputStream);
            return KeyUtil.loadECPrivateKey(data);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public static PrivateKey loadPrivateKey(String resourcePath) {
        ResourceLoader resourceLoader = new DefaultResourceLoader();
        Resource resource = resourceLoader.getResource(resourcePath);
        return loadPrivateKeyFromResource(resource);
    }

    public static Authenticator createAuthenticator(AttestationObject attestationObject) {
        AttestedCredentialData attestedCredentialData = attestationObject.getAuthenticatorData().getAttestedCredentialData();
        return new AuthenticatorImpl(attestedCredentialData, attestationObject.getAttestationStatement(), attestationObject.getAuthenticatorData().getSignCount());
    }

    public static TrustAnchorProvider createTrustAnchorProviderWith2tierTestRootCACertificate() {
        return () -> {
            Set<TrustAnchor> set = new HashSet<>();
            set.add(new TrustAnchor(load2tierTestRootCACertificate(), null));
            return set;
        };
    }

    public static TrustAnchorProvider createTrustAnchorProviderWith3tierTestRootCACertificate() {
        return () -> {
            Set<TrustAnchor> set = new HashSet<>();
            set.add(new TrustAnchor(load3tierTestRootCACertificate(), null));
            return set;
        };
    }

}
