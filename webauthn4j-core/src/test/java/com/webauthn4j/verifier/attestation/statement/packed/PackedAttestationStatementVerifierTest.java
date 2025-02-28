package com.webauthn4j.verifier.attestation.statement.packed;

import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.AuthenticatorDataConverter;
import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.attestation.statement.AttestationCertificatePath;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.attestation.statement.PackedAttestationStatement;
import com.webauthn4j.data.client.ClientDataType;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.extension.authenticator.ExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.test.TestAttestationUtil;
import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.util.Base64UrlUtil;
import com.webauthn4j.util.MessageDigestUtil;
import com.webauthn4j.util.RSAUtil;
import com.webauthn4j.util.exception.UnexpectedCheckedException;
import com.webauthn4j.verifier.RegistrationObject;
import com.webauthn4j.verifier.exception.BadAttestationStatementException;
import com.webauthn4j.verifier.exception.BadSignatureException;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertThrows;


@SuppressWarnings({"FieldCanBeLocal", "SameParameterValue", "ConstantConditions"})
class PackedAttestationStatementVerifierTest {

    private final ObjectConverter objectConverter = new ObjectConverter();

    private final PackedAttestationStatementVerifier target = new PackedAttestationStatementVerifier();

    private final String originUrl = "http://localhost:8800";
    private final String rpId = "localhost";
    private final String challengeString = "KG8gySc5IaMvPQOWJz93R4OQQb3mdGjQwkQ89_HPe-E";
    private final byte[] tokenBindingId = null;

    private static AttestationCertificatePath generateCertPath(KeyPair pair, String signAlg) {

        try {
            Provider bcProvider = new BouncyCastleProvider();
            //Security.addProvider(bcProvider);

            long now = System.currentTimeMillis();
            Date from = new Date(now);
            Date to = new Date(from.getTime() + TimeUnit.DAYS.toMillis(1));

            X500Name dnName = new X500Name("C=ORG, O=Dummy Org, OU=Authenticator Attestation, CN=Dummy");
            BigInteger certSerialNumber = BigInteger.ZERO;

            Calendar calendar = Calendar.getInstance();
            calendar.setTime(from);
            calendar.add(Calendar.YEAR, 1);

            ContentSigner contentSigner = new JcaContentSignerBuilder(signAlg).build(pair.getPrivate());
            JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(dnName, certSerialNumber, from, to, dnName, pair.getPublic());

            BasicConstraints basicConstraints = new BasicConstraints(false);
            certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"), true, basicConstraints);

            X509Certificate certificate = new JcaX509CertificateConverter().setProvider(bcProvider).getCertificate(certBuilder.build(contentSigner));
            return new AttestationCertificatePath(Collections.singletonList(certificate));
        } catch (OperatorCreationException | CertificateException | CertIOException e) {
            throw new UnexpectedCheckedException(e);
        }
    }

    @Test
    void verifyAttestationStatementNotNull_test() {
        PackedAttestationStatement attestationStatement = new PackedAttestationStatement(COSEAlgorithmIdentifier.ES256, new byte[32], new AttestationCertificatePath());
        target.verifyAttestationStatementNotNull(attestationStatement);
    }

    @Test
    void verifyAttestationStatementNotNull_with_null_test() {
        assertThatThrownBy(() -> target.verifyAttestationStatementNotNull(null)).isInstanceOf(BadAttestationStatementException.class);
    }

    @Test
    void verifyAttestationStatementNotNull_x5C_null_test() {
        PackedAttestationStatement attestationStatement = new PackedAttestationStatement(COSEAlgorithmIdentifier.ES256, new byte[32], null);
        assertThatCode(() -> target.verifyAttestationStatementNotNull(attestationStatement)).doesNotThrowAnyException();
    }


    @Test
    void verify_with_ECx5C_test() {
        byte[] clientData = TestDataUtil.createClientDataJSON(ClientDataType.WEBAUTHN_CREATE);
        byte[] clientDataHash = MessageDigestUtil.createSHA256().digest(clientData);
        AttestationObject attestationObject = TestDataUtil.createAttestationObjectWithBasicPackedECAttestationStatement(clientDataHash);

        verify(clientData, attestationObject);
    }

    @Test
    void verify_with_RSAx5C_test() throws Exception {
        KeyPair keyPair = RSAUtil.createKeyPair();
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData = TestDataUtil.createAuthenticatorData();

        byte[] clientData = TestDataUtil.createClientDataJSON(ClientDataType.WEBAUTHN_CREATE);
        byte[] signature = generateSignature("SHA256withRSA", keyPair, authenticatorData, clientData);

        AttestationCertificatePath x5c = generateCertPath(keyPair, "SHA256withRSA");
        PackedAttestationStatement packedAttestationStatement = new PackedAttestationStatement(COSEAlgorithmIdentifier.RS256, signature, x5c);
        AttestationObject attestationObject = new AttestationObject(authenticatorData, packedAttestationStatement);

        verify(clientData, attestationObject);
    }


    @Test
    void verify_with_yubikey_fido2_data_test() {
        byte[] attestationObjectBytes = Base64UrlUtil.decode("o2NmbXRmcGFja2VkaGF1dGhEYXRhWJRJlg3liA6MaHQ0Fw9kdmBbj-SuuaKGMseZXPO6gx2XY0UAAAADbUS6m_bsLkm5MAyP6SDLcwAQpt-LSNKw2Ni2n3k1ltLMrqUBAgMmIAEhWCA6CWZ7k4UFMb5kynCGxmRhRVTvppyLpwBKmZ1m96qSjiJYID1KElygcTfTMT5RRoU0oAbBoZEfjHUZytXNemDDkuZpZ2F0dFN0bXSjY2FsZyZjc2lnWEYwRAIgTqgNTx1zMoc4L1Eb_dOgyqtouZBVfrQscgsGrgE4lRICICLuRuy1T05B1kv86XzP0dnN0-DzRcU1t9tS0FTktASBY3g1Y4FZAsEwggK9MIIBpaADAgECAgQq52JjMA0GCSqGSIb3DQEBCwUAMC4xLDAqBgNVBAMTI1l1YmljbyBVMkYgUm9vdCBDQSBTZXJpYWwgNDU3MjAwNjMxMCAXDTE0MDgwMTAwMDAwMFoYDzIwNTAwOTA0MDAwMDAwWjBuMQswCQYDVQQGEwJTRTESMBAGA1UECgwJWXViaWNvIEFCMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMScwJQYDVQQDDB5ZdWJpY28gVTJGIEVFIFNlcmlhbCA3MTk4MDcwNzUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQqA4ZeYEPZnhH_EKolVFeEvwmvjmseOzIXKSFvVRIajNkQ05ndx2i9_kp7x-PavGLm0kaf9Wdbj_qJDMp0hp4_o2wwajAiBgkrBgEEAYLECgIEFTEuMy42LjEuNC4xLjQxNDgyLjEuMTATBgsrBgEEAYLlHAIBAQQEAwIEMDAhBgsrBgEEAYLlHAEBBAQSBBBtRLqb9uwuSbkwDI_pIMtzMAwGA1UdEwEB_wQCMAAwDQYJKoZIhvcNAQELBQADggEBAHJX0Dzcw-EVaYSQ1vgO-VtTByNz2eZHMmMrEdzcd4rsa9WSbQfhe5xUMHiN4y9OR7RYdv-MVSICm-k4eHlXIzHnJ3AWgopxGznHT9bBJYvR5NnlZtVweQNH2lI1wD8P_kCxQo4FxukXmeR1VHFpAe64i7BXiTWIrYiq0w1xTy8vrDbVTbrXEJxbAnqwyrjPNU7xAIoJCGyghpavDPzbwYOY_N8CMWwmIsle5iK90cAKR4nkocy3SaNUul8nYEIwvv-uBua_AvvAFbzRUd811wqYqOQtykSI_PBxBCGI3-odX3S36niLKvnFFKm6uU_nOJzaGVGQsrEwfb-RGOGpKfg=");
        byte[] clientDataBytes = Base64UrlUtil.decode("ew0KCSJ0eXBlIiA6ICJ3ZWJhdXRobi5jcmVhdGUiLA0KCSJjaGFsbGVuZ2UiIDogIno5LWxDWmFQUlBtMGFReDlLMnE4a3ciLA0KCSJvcmlnaW4iIDogImh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsDQoJInRva2VuQmluZGluZyIgOiANCgl7DQoJCSJzdGF0dXMiIDogInN1cHBvcnRlZCINCgl9DQp9");
        AttestationObject attestationObject = new AttestationObjectConverter(objectConverter).convert(attestationObjectBytes);

        verify(clientDataBytes, attestationObject);
    }


    @Test
    void verify_with_ECSelfAttestation_test() {
        byte[] clientData = TestDataUtil.createClientDataJSON(ClientDataType.WEBAUTHN_CREATE);
        byte[] clientDataHash = MessageDigestUtil.createSHA256().digest(clientData);
        AttestationObject attestationObject = TestDataUtil.createAttestationObjectWithSelfPackedECAttestationStatement(clientDataHash);

        verify(clientData, attestationObject);
    }

    @Test
    void verify_with_ECSelfAttestationPS256_test() {
        byte[] clientData = TestDataUtil.createClientDataJSON(ClientDataType.WEBAUTHN_CREATE);
        byte[] clientDataHash = MessageDigestUtil.createSHA256().digest(clientData);
        Provider bcProvider = new BouncyCastleProvider();
        Security.addProvider(bcProvider);
        AttestationObject attestationObject = TestDataUtil.createAttestationObjectWithSelfPackedECAttestationStatementPS256(clientDataHash);

        verify(clientData, attestationObject);
    }

    @Test
    void verify_with_RSASelfAttestation_test() {
        byte[] clientData = TestDataUtil.createClientDataJSON(ClientDataType.WEBAUTHN_CREATE);
        byte[] clientDataHash = MessageDigestUtil.createSHA256().digest(clientData);
        AttestationObject attestationObject = TestDataUtil.createAttestationObjectWithSelfPackedRSAAttestationStatement(clientDataHash);

        verify(clientData, attestationObject);

    }

    @Test
    void verify_with_invalid_AttestationStatement_test() {
        byte[] clientData = TestDataUtil.createClientDataJSON(ClientDataType.WEBAUTHN_CREATE);
        AttestationObject attestationObject = TestDataUtil.createAttestationObjectWithFIDOU2FAttestationStatement();
        assertThrows(IllegalArgumentException.class,
                () -> verify(clientData, attestationObject)
        );
    }

    @Test
    void verify_with_bad_signature_test() {
        byte[] clientData = TestDataUtil.createClientDataJSON(ClientDataType.WEBAUTHN_CREATE);
        byte[] clientDataHash = new byte[32];
        AttestationObject attestationObject = TestDataUtil.createAttestationObjectWithBasicPackedECAttestationStatement(clientDataHash);

        assertThrows(BadSignatureException.class,
                () -> verify(clientData, attestationObject)
        );
    }

    @Test
    void extractAAGUIDFromAttestationCertificate_with_u2f_attestation_test() {
        AAGUID aaguid = target.extractAAGUIDFromAttestationCertificate(TestAttestationUtil.loadYubikeyU2FAttestationCertificate());
        assertThat(aaguid).isEqualTo(AAGUID.NULL);
    }

    @Test
    void extractAAGUIDFromAttestationCertificate_with_fido2_attestation_test() {
        AAGUID aaguid = target.extractAAGUIDFromAttestationCertificate(TestAttestationUtil.loadYubikeyFIDO2AttestationCertificate());
        assertThat(aaguid).isNotEqualTo(AAGUID.NULL);
    }

    private void verify(byte[] clientDataBytes, AttestationObject attestationObject) {

        byte[] attestationObjectBytes = new AttestationObjectConverter(objectConverter).convertToBytes(attestationObject);

        Origin origin = new Origin(originUrl);
        Challenge challenge = (Challenge) () -> Base64UrlUtil.decode(challengeString);

        CollectedClientData collectedClientData = new CollectedClientDataConverter(objectConverter).convert(clientDataBytes);
        Set<AuthenticatorTransport> transports = Collections.emptySet();
        AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> authenticationExtensionsClientOutputs = new AuthenticationExtensionsClientOutputs<>();

        RegistrationObject registrationObject = new RegistrationObject(
                attestationObject,
                attestationObjectBytes,
                collectedClientData,
                clientDataBytes,
                authenticationExtensionsClientOutputs,
                transports,
                new ServerProperty(origin, rpId, challenge, tokenBindingId)
        );

        target.verify(registrationObject);
    }

    private <T extends ExtensionAuthenticatorOutput> byte[] generateSignature(String signAlg, KeyPair keyPair, AuthenticatorData<T> data, byte[] clientDataJSON) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        byte[] authenticatorData = new AuthenticatorDataConverter(objectConverter).convert(data);
        byte[] clientDataHash = MessageDigestUtil.createSHA256().digest(clientDataJSON);

        byte[] signedData = ByteBuffer.allocate(authenticatorData.length + clientDataHash.length).put(authenticatorData).put(clientDataHash).array();

        Signature sig = Signature.getInstance(signAlg);
        sig.initSign(keyPair.getPrivate());
        sig.update(signedData);
        return sig.sign();
    }
}