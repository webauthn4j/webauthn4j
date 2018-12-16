package com.webauthn4j.validator.attestation.packed;

import com.webauthn4j.attestation.AttestationObject;
import com.webauthn4j.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.attestation.statement.AttestationCertificatePath;
import com.webauthn4j.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.attestation.statement.PackedAttestationStatement;
import com.webauthn4j.client.ClientDataType;
import com.webauthn4j.client.CollectedClientData;
import com.webauthn4j.client.Origin;
import com.webauthn4j.client.challenge.Challenge;
import com.webauthn4j.client.challenge.DefaultChallenge;
import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.AuthenticatorDataConverter;
import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.registry.Registry;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.test.TestUtil;
import com.webauthn4j.util.Base64UrlUtil;
import com.webauthn4j.util.KeyUtil;
import com.webauthn4j.util.MessageDigestUtil;
import com.webauthn4j.util.exception.NotImplementedException;
import com.webauthn4j.validator.RegistrationObject;
import com.webauthn4j.validator.exception.BadSignatureException;
import com.webauthn4j.validator.exception.UnsupportedAttestationFormatException;
import org.junit.Test;
import sun.security.x509.*;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.Collections;
import java.util.Date;
import java.util.concurrent.TimeUnit;


public class PackedAttestationStatementValidatorTest {

    private Registry registry = new Registry();

    private PackedAttestationStatementValidator validator = new PackedAttestationStatementValidator();

    private String originUrl = "http://localhost:8800";
    private String rpId = "localhost";
    private String challengeString = "KG8gySc5IaMvPQOWJz93R4OQQb3mdGjQwkQ89_HPe-E";
    private byte[] tokenBindingId = null;

    @Test
    public void validate_with_ECx5c_test() {
        byte[] clientData = TestUtil.createClientDataJSON(ClientDataType.CREATE);
        byte[] clientDataHash = MessageDigestUtil.createSHA256().digest(clientData);
        AttestationObject attestationObject = TestUtil.createAttestationObjectWithBasicPackedECAttestationStatement(clientDataHash);

        validate(clientData, attestationObject);
    }

    @Test
    public void validate_with_RSAx5c_test() throws Exception {
        KeyPair keyPair = KeyUtil.createRSAKeyPair();
        AuthenticatorData authenticatorData = TestUtil.createAuthenticatorData();

        byte[] clientData = TestUtil.createClientDataJSON(ClientDataType.CREATE);
        byte[] signature = generateSignature("SHA256withRSA", keyPair, authenticatorData, clientData);

        AttestationCertificatePath x5c = generateCertPath(keyPair, "SHA256withRSA");
        PackedAttestationStatement packedAttestationStatement = new PackedAttestationStatement(COSEAlgorithmIdentifier.RS256, signature, x5c, null);
        AttestationObject attestationObject = new AttestationObject(authenticatorData, packedAttestationStatement);

        validate(clientData, attestationObject);
    }

    @Test
    public void validate_with_ECselfAttestation_test() {
        byte[] clientData = TestUtil.createClientDataJSON(ClientDataType.CREATE);
        byte[] clientDataHash = MessageDigestUtil.createSHA256().digest(clientData);
        AttestationObject attestationObject = TestUtil.createAttestationObjectWithSelfPackedECAttestationStatement(clientDataHash);

        validate(clientData, attestationObject);
    }


    @Test
    public void validate_with_RSAselfAttestation_test() {
        byte[] clientData = TestUtil.createClientDataJSON(ClientDataType.CREATE);
        byte[] clientDataHash = MessageDigestUtil.createSHA256().digest(clientData);
        AttestationObject attestationObject = TestUtil.createAttestationObjectWithSelfPackedRSAAttestationStatement(clientDataHash);

        validate(clientData, attestationObject);

    }

    @Test(expected = NotImplementedException.class)
    public void validate_with_ecdaaKeyId_test() throws Exception {
        KeyPair keyPair = KeyUtil.createECKeyPair();
        AuthenticatorData authenticatorData = TestUtil.createAuthenticatorData();

        byte[] clientData = TestUtil.createClientDataJSON(ClientDataType.CREATE, new DefaultChallenge(challengeString));
        byte[] signature = generateSignature("SHA256withECDSA", keyPair, authenticatorData, clientData);

        byte[] ecdaaKeyId = new byte[16];
        AttestationObject attestationObject = new AttestationObject(authenticatorData, new PackedAttestationStatement(COSEAlgorithmIdentifier.ES256, signature, null, ecdaaKeyId));

        validate(clientData, attestationObject);
    }

    @Test(expected = UnsupportedAttestationFormatException.class)
    public void validate_with_invalid_AttestationStatement_test(){
        byte[] clientData = TestUtil.createClientDataJSON(ClientDataType.CREATE);
        AttestationObject attestationObject = TestUtil.createAttestationObjectWithFIDOU2FAttestationStatement();
        validate(clientData, attestationObject);
    }

    @Test(expected = BadSignatureException.class)
    public void validate_with_bad_signature_test() {
        byte[] clientData = TestUtil.createClientDataJSON(ClientDataType.CREATE);
        byte[] clientDataHash = new byte[32];
        AttestationObject attestationObject = TestUtil.createAttestationObjectWithBasicPackedECAttestationStatement(clientDataHash);

        validate(clientData, attestationObject);
    }

    private void validate(byte[] clientDataBytes, AttestationObject attestationObject) {

        byte[] attestationObjectBytes = new AttestationObjectConverter(registry).convertToBytes(attestationObject);

        Origin origin = new Origin(originUrl);
        Challenge challenge = (Challenge) () -> Base64UrlUtil.decode(challengeString);

        AttestationObjectConverter attestationObjectConverter = new AttestationObjectConverter(registry);
        CollectedClientData collectedClientData = new CollectedClientDataConverter(registry).convert(clientDataBytes);

        RegistrationObject registrationObject = new RegistrationObject(
                collectedClientData,
                clientDataBytes,
                attestationObject,
                attestationObjectBytes,
                attestationObjectConverter.extractAuthenticatorData(attestationObjectBytes),
                new ServerProperty(origin, rpId, challenge, tokenBindingId)
        );

        validator.validate(registrationObject);
    }

    private byte[] generateSignature(String signAlgo, KeyPair keyPair, AuthenticatorData data, byte[] clientDataJSON) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        byte[] authenticatorData = new AuthenticatorDataConverter(registry).convert(data);
        byte[] clientDataHash = MessageDigestUtil.createSHA256().digest(clientDataJSON);

        byte[] signedData = ByteBuffer.allocate(authenticatorData.length + clientDataHash.length).put(authenticatorData).put(clientDataHash).array();

        Signature sig = Signature.getInstance(signAlgo);
        sig.initSign(keyPair.getPrivate());
        sig.update(signedData);
        return sig.sign();
    }

    private static AttestationCertificatePath generateCertPath(KeyPair pair, String signAlgo) {
        try {


            X500Name owner = new X500Name("C=ORG, O=Dummy Org, OU=Authenticator Attestation, CN=Dummy");

            Date from = new Date();
            Date to = new Date(from.getTime() + TimeUnit.DAYS.toMillis(1));
            CertificateValidity interval = new CertificateValidity(from, to);
            BigInteger sn = new BigInteger(64, new SecureRandom());

            X509CertInfo info = new X509CertInfo();
            info.set(X509CertInfo.VALIDITY, interval);
            info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(sn));
            info.set(X509CertInfo.SUBJECT, owner);
            info.set(X509CertInfo.ISSUER, owner);
            info.set(X509CertInfo.KEY, new CertificateX509Key(pair.getPublic()));
            info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
            AlgorithmId algo = new AlgorithmId(AlgorithmId.md5WithRSAEncryption_oid);
            info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algo));

            // Sign the cert to identify the algorithm that's used.
            X509CertImpl x509 = new X509CertImpl(info);
            x509.sign(pair.getPrivate(), signAlgo);


            return new AttestationCertificatePath(Collections.singletonList(x509));
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }


    }
}