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

import com.webauthn4j.anchor.TrustAnchorsResolver;
import com.webauthn4j.data.attestation.statement.AttestationCertificatePath;
import com.webauthn4j.util.Base64UrlUtil;
import com.webauthn4j.util.CertificateUtil;
import com.webauthn4j.util.exception.UnexpectedCheckedException;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.util.StreamUtils;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.sql.Date;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class TestAttestationUtil {

    private TestAttestationUtil(){}

    // ~ Public key certificate chains
    // ========================================================================================================

    public static AttestationCertificatePath load3tierTestAttestationCertificatePath() {
        return new AttestationCertificatePath(Arrays.asList(load3tierTestAuthenticatorAttestationCertificate(), load3tierTestIntermediateCACertificate()));
    }

    public static CACertificatePath load3tierTestCACertificatePath() {
        return new CACertificatePath(Collections.singletonList(load3tierTestIntermediateCACertificate()));
    }

    public static AttestationCertificatePath load2tierTestAttestationCertificatePath() {
        return new AttestationCertificatePath(Collections.singletonList(load2tierTestAuthenticatorAttestationCertificate()));
    }

    // ~ Trust Anchors
    // ========================================================================================================

    public static TrustAnchorsResolver createTrustAnchorProviderWith2tierTestRootCACertificate() {
        return (aaguid) -> {
            Set<TrustAnchor> set = new HashSet<>();
            set.add(new TrustAnchor(load2tierTestRootCACertificate(), null));
            return set;
        };
    }

    public static TrustAnchorsResolver createTrustAnchorProviderWith3tierTestRootCACertificate() {
        return (aaguid) -> {
            Set<TrustAnchor> set = new HashSet<>();
            set.add(new TrustAnchor(load3tierTestRootCACertificate(), null));
            return set;
        };
    }

    // ~ Public key certificates
    // ========================================================================================================

    public static X509Certificate loadAndroidKeyAttestationCertificate() {
        String certificate =
                "-----BEGIN CERTIFICATE-----\n"
                        + "MIIByTCCAXCgAwIBAgIBATAKBggqhkjOPQQDAjAcMRowGAYDVQQDDBFBbmRyb2lkIE"
                        + "tleW1hc3Rl cjAgFw03MDAxMDEwMDAwMDBaGA8yMTA2MDIwNzA2MjgxNVowGjEYMBY"
                        + "GA1UEAwwPQSBLZXltYXN0 ZXIgS2V5MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE"
                        + "FpsFUWID9p2QPAvtfal4MRf9vJg0tNc3 vKJwoDhhSCMm7If0FljgvmroBYQyCIbnn"
                        + "Bxh2OU9SKxI/manPwIIUqOBojCBnzALBgNVHQ8EBAMC B4AwbwYKKwYBBAHWeQIBEQ"
                        + "RhMF8CAQEKAQACAQEKAQEEBWhlbGxvBAAwDL+FPQgCBgFWDy29GDA6 oQUxAwIBAqI"
                        + "DAgEDowQCAgEApQUxAwIBBKoDAgEBv4N4AwIBA7+DeQQCAgEsv4U+AwIBAL+FPwIF "
                        + "ADAfBgNVHSMEGDAWgBQ//KzWGrE6noEguNUlHMVlux6RqTAKBggqhkjOPQQDAgNHAD"
                        + "BEAiBKzJSk 9VNauKu4dr+ZJ5jMTNlAxSI99XkKEkXSolsGSAIgCnd5T99gv3B/IqM"
                        + "CHn0yZ7Wuu/jisU0epRRo xh8otA8=\n"
                        + "-----END CERTIFICATE-----";
        return createCertificate(certificate);
    }

    public static X509Certificate loadAndroidKeyIntermidiateCertificate() {
        String certificate =
                "-----BEGIN CERTIFICATE-----\n" +
                        "MIICeDCCAh6gAwIBAgICEAEwCgYIKoZIzj0EAwIwgZgxCzAJBgNVBAYTAlVTMRMwEQ"
                        + "YDVQQIDApD YWxpZm9ybmlhMRYwFAYDVQQHDA1Nb3VudGFpbiBWaWV3MRUwEwYDVQQ"
                        + "KDAxHb29nbGUsIEluYy4x EDAOBgNVBAsMB0FuZHJvaWQxMzAxBgNVBAMMKkFuZHJv"
                        + "aWQgS2V5c3RvcmUgU29mdHdhcmUgQXR0 ZXN0YXRpb24gUm9vdDAeFw0xNjAxMTEwM"
                        + "DQ2MDlaFw0yNjAxMDgwMDQ2MDlaMIGIMQswCQYDVQQG EwJVUzETMBEGA1UECAwKQ2"
                        + "FsaWZvcm5pYTEVMBMGA1UECgwMR29vZ2xlLCBJbmMuMRAwDgYDVQQL DAdBbmRyb2l"
                        + "kMTswOQYDVQQDDDJBbmRyb2lkIEtleXN0b3JlIFNvZnR3YXJlIEF0dGVzdGF0aW9u "
                        + "IEludGVybWVkaWF0ZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOueefhCY1msyy"
                        + "qRTImGzHCt kGaTgqlzJhP+rMv4ISdMIXSXSir+pblNf2bU4GUQZjW8U7ego6ZxWD7"
                        + "bPhGuEBSjZjBkMB0GA1Ud DgQWBBQ//KzWGrE6noEguNUlHMVlux6RqTAfBgNVHSME"
                        + "GDAWgBTIrel3TEXDo88NFhDkeUM6IVow zzASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA"
                        + "1UdDwEB/wQEAwIChDAKBggqhkjOPQQDAgNIADBFAiBL ipt77oK8wDOHri/AiZi03c"
                        + "ONqycqRZ9pDMfDktQPjgIhAO7aAV229DLp1IQ7YkyUBO86fMy9Xvsi u+f+uXc/WT/"
                        + "7\n" +
                        "-----END CERTIFICATE-----";
        return createCertificate(certificate);
    }

    /**
     * Creates {@link X509Certificate} from PEM style certificate string.
     *
     * @param derEncodedCertificate DER-encoded certificate. Please note it is encoded in base64 string, not base64url.
     * @return created X509Certificate
     */
    public static X509Certificate createCertificate(String derEncodedCertificate) {
        return CertificateUtil.generateX509Certificate(derEncodedCertificate.getBytes());
    }

    public static X509Certificate createV1DummyCertificate(){
        try{
            X509v1CertificateBuilder certificateBuilder = new X509v1CertificateBuilder(
                    new X500Name("O=SharpLab., C=US"),
                    BigInteger.valueOf(1),
                    Date.from(Instant.parse("2000-01-01T00:00:00Z")),
                    Date.from(Instant.parse("2999-12-31T23:59:59Z")),
                    new X500Name("O=SharpLab., C=US"),
                    new SubjectPublicKeyInfo(new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256WITHRSA"), new byte[0])
            );
            ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA").build(KeyUtil.createRSAKeyPair().getPrivate());
            X509CertificateHolder certificateHolder = certificateBuilder.build(contentSigner);
            try {
                return new JcaX509CertificateConverter().getCertificate(certificateHolder);
            } catch (CertificateException e) {
                throw new com.webauthn4j.validator.exception.CertificateException(e);
            }
        } catch (OperatorCreationException e) {
            throw new UnexpectedCheckedException(e);
        }
    }

    public static X509Certificate loadCertificateFromResource(Resource resource) {
        try {
            return CertificateUtil.generateX509Certificate(resource.getInputStream());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public static X509Certificate loadCertificateFromResourcePath(String resourcePath) {
        ResourceLoader resourceLoader = new DefaultResourceLoader();
        Resource resource = resourceLoader.getResource(resourcePath);
        return loadCertificateFromResource(resource);
    }

    public static X509Certificate loadFirefoxSWTokenAttestationCertificate() {
        String base64UrlCertificate = "MIIBMTCB2KADAgECAgRdWm5nMAoGCCqGSM49BAMCMCExHzAdBgNVBAMTFkZpcmVmb3ggVTJGIFNvZnQgVG9rZW4wHhcNMTcwODE5MTExMDI3WhcNMTcwODIxMTExMDI3WjAhMR8wHQYDVQQDExZGaXJlZm94IFUyRiBTb2Z0IFRva2VuMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmNdtc7TW47xJcunwo_5ZuqSeHKJDZixC3AhTy2OEnYZfLmLZn9ssfWqLmPY4E642bKRDsm6qLNfjj_z9ufejNTAKBggqhkjOPQQDAgNIADBFAiEA6SdHwFyOq1trbQA6TLxLHS11EYUYDWyA24BnsJD8TrACIEw7k4aGBMOYlT5uMXLlj4bV5jo1Svi83VOpBo5ykMvd";
        return CertificateUtil.generateX509Certificate(Base64UrlUtil.decode(base64UrlCertificate));
    }

    public static X509Certificate loadFeitianU2FTokenAttestationCertificate() {
        String base64UrlCertificate = "MIIBTDCB86ADAgECAgrMFgqn4TlPa3dQMAoGCCqGSM49BAMCMBcxFTATBgNVBAMTDEZUIEZJRE8gMDEwMDAeFw0xNjA0MTUxNDUwMzJaFw0yNjA0MTUxNDUwMzJaMCcxJTAjBgNVBAMTHEZUIEZJRE8gVTJGIDExNjE2MTczMDMwNTAyMTAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATG1tXh9HyGi4UJapsP3Fw8NEwRr5WEYfV5xOvP2XU4jpnJ17SEbyZTCn7rX38Ept32BPr6IaOmamqAdQvsDpNgoxcwFTATBgsrBgEEAYLlHAIBAQQEAwIEMDAKBggqhkjOPQQDAgNIADBFAiEA3wPvLOvjpbU3VCsKBjWtb5MzcX_I2p7NN_X03kyyFoUCIAxoJPinKGUxoNR_bhx3uZHtQQpwLWuaBND9y2Omhf47";
        return CertificateUtil.generateX509Certificate(Base64UrlUtil.decode(base64UrlCertificate));
    }

    public static X509Certificate loadYubikeyAttestationCertificate() {
        String base64UrlCertificate = "MIICRDCCAS6gAwIBAgIEeMDfDjALBgkqhkiG9w0BAQswLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcyMDA2MzEwIBcNMTQwODAxMDAwMDAwWhgPMjA1MDA5MDQwMDAwMDBaMCoxKDAmBgNVBAMMH1l1YmljbyBVMkYgRUUgU2VyaWFsIDIwMjU5MDU5MzQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS1uHFcg_3-DqFcRXeshY30jBdv3oedyvS4PUDTIPJvreYl_Pf1yK_YNRj4254h7Ag7GEWAxxfsSkcLlopvuj9vozswOTAiBgkrBgEEAYLECgIEFTEuMy42LjEuNC4xLjQxNDgyLjEuMTATBgsrBgEEAYLlHAIBAQQEAwIFIDALBgkqhkiG9w0BAQsDggEBAD72q_ZKkWsL-ZSTjdyVNOBUQAJoVninLEOnq-ZdkGX_YfRRzoo67thmidGQuVCvAHpU0THu8G_ia06nuz4yt5IFpd-nYAQ0U-NK-ETDfNSoX4xcLYcOCiiyt-1EAkH9s3krIHaw4Yr6m0Mu7vwmWLoJBcQbJKk8bsi7ptVvM-jWU9fPa9UBVFWiZZdA99zFHMAxYJzQPqbN6Tmeygh2MpB2P7TI0A9WkGmhJUkAauuwaiGiFOSZmDe0KegdflbTOlSS3ToWHIKTlUCBqn7vdJw6Vj2919ujlcxHPkRpbUGRhcJDesg6wGTBy-RyJ_96G3fH1eoMNn1F9jC9mY1Zsm4=";
        return CertificateUtil.generateX509Certificate(Base64UrlUtil.decode(base64UrlCertificate));
    }


    public static X509Certificate load3tierTestRootCACertificate() {
        return loadCertificateFromResourcePath("classpath:attestation/3tier/certs/3tier-test-root-CA.crt");
    }

    public static X509Certificate load3tierTestIntermediateCACertificate() {
        return loadCertificateFromResourcePath("classpath:attestation/3tier/certs/3tier-test-intermediate-CA.crt");
    }

    public static X509Certificate load3tierTestAuthenticatorAttestationCertificate() {
        return loadCertificateFromResourcePath("classpath:attestation/3tier/certs/3tier-test-authenticator.crt");
    }

    public static X509Certificate load2tierTestRootCACertificate() {
        return loadCertificateFromResourcePath("classpath:attestation/2tier/certs/2tier-test-root-CA.crt");
    }

    public static X509Certificate load2tierTestAuthenticatorAttestationCertificate() {
        return loadCertificateFromResourcePath("classpath:attestation/2tier/certs/2tier-test-authenticator.crt");
    }

    // ~ Public Keys
    // ========================================================================================================
    public static PublicKey load3tierTestRootCAPublicKey() {
        return load3tierTestRootCACertificate().getPublicKey();
    }

    public static PublicKey load3tierTestIntermediateCAPublicKey() {
        return load3tierTestIntermediateCACertificate().getPublicKey();
    }

    public static PublicKey load3tierTestAuthenticatorAttestationPublicKey() {
        return load3tierTestAuthenticatorAttestationCertificate().getPublicKey();
    }

    public static PublicKey load2tierTestRootCAPublicKey() {
        return load3tierTestRootCACertificate().getPublicKey();
    }

    public static PublicKey load2tierTestAuthenticatorAttestationPublicKey() {
        return load3tierTestAuthenticatorAttestationCertificate().getPublicKey();
    }


    // ~ Private Keys
    // ========================================================================================================

    public static PrivateKey load3tierTestRootCAPrivateKey() {
        return loadPrivateKeyFromResourcePath("classpath:attestation/3tier/private/3tier-test-root-CA.der");
    }

    public static PrivateKey load3tierTestIntermediateCAPrivateKey() {
        return loadPrivateKeyFromResourcePath("classpath:attestation/3tier/private/3tier-test-intermediate-CA.der");
    }

    public static PrivateKey load3tierTestAuthenticatorAttestationPrivateKey() {
        return loadPrivateKeyFromResourcePath("classpath:attestation/3tier/private/3tier-test-authenticator.der");
    }

    public static PrivateKey load2tierTestRootCAPrivateKey() {
        return loadPrivateKeyFromResourcePath("classpath:attestation/2tier/private/2tier-test-root-CA.der");
    }

    public static PrivateKey load2tierTestAuthenticatorAttestationPrivateKey() {
        return loadPrivateKeyFromResourcePath("classpath:attestation/2tier/private/2tier-test-authenticator.der");
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

    public static PrivateKey loadPrivateKeyFromResourcePath(String resourcePath) {
        ResourceLoader resourceLoader = new DefaultResourceLoader();
        Resource resource = resourceLoader.getResource(resourcePath);
        return loadPrivateKeyFromResource(resource);
    }


}
