package com.webauthn4j.validator.attestation.statement.packed;

import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.AuthenticatorDataConverter;
import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.attestation.statement.AttestationCertificatePath;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.attestation.statement.PackedAttestationStatement;
import com.webauthn4j.data.client.ClientDataType;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.test.KeyUtil;
import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.util.Base64UrlUtil;
import com.webauthn4j.util.MessageDigestUtil;
import com.webauthn4j.util.exception.NotImplementedException;
import com.webauthn4j.util.exception.UnexpectedCheckedException;
import com.webauthn4j.validator.RegistrationObject;
import com.webauthn4j.validator.exception.BadSignatureException;
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

import static org.junit.jupiter.api.Assertions.assertThrows;


class PackedAttestationStatementValidatorTest {

    private JsonConverter jsonConverter = new JsonConverter();
    private CborConverter cborConverter = new CborConverter();

    private PackedAttestationStatementValidator validator = new PackedAttestationStatementValidator();

    private String originUrl = "http://localhost:8800";
    private String rpId = "localhost";
    private String challengeString = "KG8gySc5IaMvPQOWJz93R4OQQb3mdGjQwkQ89_HPe-E";
    private byte[] tokenBindingId = null;

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
    void validate_with_ECx5c_test() {
        byte[] clientData = TestDataUtil.createClientDataJSON(ClientDataType.CREATE);
        byte[] clientDataHash = MessageDigestUtil.createSHA256().digest(clientData);
        AttestationObject attestationObject = TestDataUtil.createAttestationObjectWithBasicPackedECAttestationStatement(clientDataHash);

        validate(clientData, attestationObject);
    }

    @Test
    void validate_with_RSAx5c_test() throws Exception {
        KeyPair keyPair = KeyUtil.createRSAKeyPair();
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData = TestDataUtil.createAuthenticatorData();

        byte[] clientData = TestDataUtil.createClientDataJSON(ClientDataType.CREATE);
        byte[] signature = generateSignature("SHA256withRSA", keyPair, authenticatorData, clientData);

        AttestationCertificatePath x5c = generateCertPath(keyPair, "SHA256withRSA");
        PackedAttestationStatement packedAttestationStatement = new PackedAttestationStatement(COSEAlgorithmIdentifier.RS256, signature, x5c, null);
        AttestationObject attestationObject = new AttestationObject(authenticatorData, packedAttestationStatement);

        validate(clientData, attestationObject);
    }

    @Test
    void validate_with_ECSelfAttestation_test() {
        byte[] clientData = TestDataUtil.createClientDataJSON(ClientDataType.CREATE);
        byte[] clientDataHash = MessageDigestUtil.createSHA256().digest(clientData);
        AttestationObject attestationObject = TestDataUtil.createAttestationObjectWithSelfPackedECAttestationStatement(clientDataHash);

        validate(clientData, attestationObject);
    }

    @Test
    void validate_with_RSASelfAttestation_test() {
        byte[] clientData = TestDataUtil.createClientDataJSON(ClientDataType.CREATE);
        byte[] clientDataHash = MessageDigestUtil.createSHA256().digest(clientData);
        AttestationObject attestationObject = TestDataUtil.createAttestationObjectWithSelfPackedRSAAttestationStatement(clientDataHash);

        validate(clientData, attestationObject);

    }

    @Test
    void validate_with_ecdaaKeyId_test() throws Exception {
        KeyPair keyPair = KeyUtil.createECKeyPair();
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData = TestDataUtil.createAuthenticatorData();

        byte[] clientData = TestDataUtil.createClientDataJSON(ClientDataType.CREATE, new DefaultChallenge(challengeString));
        byte[] signature = generateSignature("SHA256withECDSA", keyPair, authenticatorData, clientData);

        byte[] ecdaaKeyId = new byte[16];
        AttestationObject attestationObject = new AttestationObject(authenticatorData, new PackedAttestationStatement(COSEAlgorithmIdentifier.ES256, signature, null, ecdaaKeyId));

        assertThrows(NotImplementedException.class,
                () -> validate(clientData, attestationObject)
        );
    }

    @Test
    void validate_with_invalid_AttestationStatement_test() {
        byte[] clientData = TestDataUtil.createClientDataJSON(ClientDataType.CREATE);
        AttestationObject attestationObject = TestDataUtil.createAttestationObjectWithFIDOU2FAttestationStatement();
        assertThrows(IllegalArgumentException.class,
                () -> validate(clientData, attestationObject)
        );
    }

    @Test
    void validate_with_bad_signature_test() {
        byte[] clientData = TestDataUtil.createClientDataJSON(ClientDataType.CREATE);
        byte[] clientDataHash = new byte[32];
        AttestationObject attestationObject = TestDataUtil.createAttestationObjectWithBasicPackedECAttestationStatement(clientDataHash);

        assertThrows(BadSignatureException.class,
                () -> validate(clientData, attestationObject)
        );
    }

    private void validate(byte[] clientDataBytes, AttestationObject attestationObject) {

        byte[] attestationObjectBytes = new AttestationObjectConverter(cborConverter).convertToBytes(attestationObject);

        Origin origin = new Origin(originUrl);
        Challenge challenge = (Challenge) () -> Base64UrlUtil.decode(challengeString);

        AttestationObjectConverter attestationObjectConverter = new AttestationObjectConverter(cborConverter);
        CollectedClientData collectedClientData = new CollectedClientDataConverter(jsonConverter).convert(clientDataBytes);
        Set<AuthenticatorTransport> transports = Collections.emptySet();
        AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> authenticationExtensionsClientOutputs = new AuthenticationExtensionsClientOutputs<>();

        RegistrationObject registrationObject = new RegistrationObject(
                collectedClientData,
                clientDataBytes,
                attestationObject,
                attestationObjectBytes,
                attestationObjectConverter.extractAuthenticatorData(attestationObjectBytes),
                transports,
                authenticationExtensionsClientOutputs,
                new ServerProperty(origin, rpId, challenge, tokenBindingId)
        );

        validator.validate(registrationObject);
    }

    private byte[] generateSignature(String signAlgo, KeyPair keyPair, AuthenticatorData data, byte[] clientDataJSON) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        byte[] authenticatorData = new AuthenticatorDataConverter(cborConverter).convert(data);
        byte[] clientDataHash = MessageDigestUtil.createSHA256().digest(clientDataJSON);

        byte[] signedData = ByteBuffer.allocate(authenticatorData.length + clientDataHash.length).put(authenticatorData).put(clientDataHash).array();

        Signature sig = Signature.getInstance(signAlgo);
        sig.initSign(keyPair.getPrivate());
        sig.update(signedData);
        return sig.sign();
    }
}