package com.webauthn4j.validator.attestation.packed;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.webauthn4j.attestation.AttestationObject;
import com.webauthn4j.attestation.authenticator.*;
import com.webauthn4j.attestation.statement.AttestationCertificatePath;
import com.webauthn4j.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.attestation.statement.PackedAttestationStatement;
import com.webauthn4j.client.CollectedClientData;
import com.webauthn4j.client.Origin;
import com.webauthn4j.client.challenge.Challenge;
import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.AuthenticatorDataConverter;
import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.registry.Registry;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.exception.NotImplementedException;
import com.webauthn4j.validator.RegistrationObject;
import org.junit.Test;
import sun.security.x509.*;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import static com.webauthn4j.attestation.authenticator.AuthenticatorData.BIT_AT;
import static com.webauthn4j.attestation.authenticator.AuthenticatorData.BIT_UP;

public class PackedAttestationStatementValidatorTest {

    private Registry registry = new Registry();
    private static Base64.Decoder decoder = Base64.getUrlDecoder();

    private PackedAttestationStatementValidator validator = new PackedAttestationStatementValidator();

    private String originUrl = "http://127.0.0.1:8800";
    private String rpId = "127.0.0.1";
    private String challengeString = "KG8gySc5IaMvPQOWJz93R4OQQb3mdGjQwkQ89_HPe-E";
    private byte[] aaGuid = new byte[16];
    private byte[] credentialId = generateRandom(32);
    private byte[] rpIdHash = hash("127.0.0.1".getBytes());
    private byte[] tokenBindingId;


    @Test
    public void selfAttestationWithEC() throws Exception {
        KeyPair keyPair = generateKeyPair("EC", new ECGenParameterSpec("secp256r1"));
        AuthenticatorData data = createAuthenticatorData(keyPair.getPublic(), aaGuid, credentialId, rpIdHash);

        byte[] clientData = generateClientData(originUrl, challengeString);
        byte[] signature = generateSignature("SHA256withECDSA", keyPair, data, clientData);

        AttestationObject attestationObject = new AttestationObject(data, new PackedAttestationStatement(COSEAlgorithmIdentifier.ES256, signature, null, null));

        validate(clientData, attestationObject);

    }

    @Test
    public void selfAttestationWithRSA() throws Exception {

        KeyPair keyPair = generateKeyPair("RSA", new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4));
        AuthenticatorData data = createAuthenticatorData(keyPair.getPublic(), aaGuid, credentialId, rpIdHash);

        byte[] clientData = generateClientData(originUrl, challengeString);
        byte[] signature = generateSignature("SHA256withRSA", keyPair, data, clientData);

        AttestationObject attestationObject = new AttestationObject(data, new PackedAttestationStatement(COSEAlgorithmIdentifier.RS256, signature, null, null));

        validate(clientData, attestationObject);

    }

    @Test
    public void x5cWithEC() throws Exception {
        KeyPair keyPair = generateKeyPair("EC", new ECGenParameterSpec("secp256r1"));
        AuthenticatorData data = createAuthenticatorData(keyPair.getPublic(), aaGuid, credentialId, rpIdHash);

        byte[] clientData = generateClientData(originUrl, challengeString);
        byte[] signature = generateSignature("SHA256withECDSA", keyPair, data, clientData);

        AttestationCertificatePath x5c = null;
        AttestationObject attestationObject = new AttestationObject(data, new PackedAttestationStatement(COSEAlgorithmIdentifier.ES256, signature, generateCertPath(keyPair, "SHA256withECDSA"), null));

        validate(clientData, attestationObject);
    }

    @Test
    public void x5cWithRSA() throws Exception {
        KeyPair keyPair = generateKeyPair("RSA", new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4));
        AuthenticatorData data = createAuthenticatorData(keyPair.getPublic(), aaGuid, credentialId, rpIdHash);

        byte[] clientData = generateClientData(originUrl, challengeString);
        byte[] signature = generateSignature("SHA256withRSA", keyPair, data, clientData);

        AttestationCertificatePath x5c = null;
        AttestationObject attestationObject = new AttestationObject(data, new PackedAttestationStatement(COSEAlgorithmIdentifier.RS256, signature, generateCertPath(keyPair, "SHA256withRSA"), null));

        validate(clientData, attestationObject);
    }

    @Test(expected = NotImplementedException.class)
    public void ecdaaKeyId() throws Exception {
        KeyPair keyPair = generateKeyPair("EC", new ECGenParameterSpec("secp256r1"));
        AuthenticatorData data = createAuthenticatorData(keyPair.getPublic(), aaGuid, credentialId, rpIdHash);

        byte[] clientData = generateClientData(originUrl, challengeString);
        byte[] signature = generateSignature("SHA256withECDSA", keyPair, data, clientData);

        byte[] ecdaaKeyId = new byte[16];
        AttestationObject attestationObject = new AttestationObject(data, new PackedAttestationStatement(COSEAlgorithmIdentifier.ES256, signature, null, ecdaaKeyId));

        validate(clientData, attestationObject);
    }

    private void validate(byte[] clientDataBytes, AttestationObject attestationObject) {

        byte[] attestationObjectBytes = new AttestationObjectConverter(registry).convertToBytes(attestationObject);

        Origin origin = new Origin(originUrl);
        Challenge challenge = (Challenge) () -> decoder.decode(challengeString);

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


    private static KeyPair generateKeyPair(String authKeyAlgorithm, AlgorithmParameterSpec algoSpecs) throws Exception {
        KeyPairGenerator kg = KeyPairGenerator.getInstance(authKeyAlgorithm);
        kg.initialize(algoSpecs, new SecureRandom());
        return kg.generateKeyPair();
    }


    public static AuthenticatorData createAuthenticatorData(PublicKey publicKey, byte[] aaGuid, byte[] credentialId, byte[] rpIdHash) {
        CredentialPublicKey credpublicKey = null;
        if (publicKey instanceof ECPublicKey) {
            credpublicKey = EC2CredentialPublicKey.create((ECPublicKey) publicKey);
        } else if (publicKey instanceof RSAPublicKey) {
            RSAPublicKey rsa = (RSAPublicKey) publicKey;
            credpublicKey = new RSACredentialPublicKey(null, COSEAlgorithmIdentifier.RS256, null, null, rsa.getModulus().toByteArray(), rsa.getPublicExponent().toByteArray());
        }

        byte flags = BIT_UP | BIT_AT;
        AttestedCredentialData credentialData = new AttestedCredentialData(aaGuid, credentialId, credpublicKey);
        return new AuthenticatorData(rpIdHash, flags, 1, credentialData);
    }

    public static byte[] hash(byte[] content) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            return sha256.digest(content);
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }

    private static byte[] generateRandom(int size) {
        SecureRandom random = new SecureRandom();
        byte[] aaGuid = new byte[size];
        random.nextBytes(aaGuid);
        return aaGuid;
    }

    private static byte[] generateClientData(String originUrl, String challengeString) throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        JsonNode json = mapper.createObjectNode();

        ((ObjectNode) json).put("type", "webauthn.create");
        ((ObjectNode) json).put("orgin", originUrl);
        ((ObjectNode) json).put("challenge", challengeString);

        return mapper.writeValueAsString(json).getBytes();
    }

    private byte[] generateSignature(String signAlgo, KeyPair keyPair, AuthenticatorData data, byte[] clientDataJSON) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        byte[] authenticatorData = new AuthenticatorDataConverter(registry).convert(data);
        byte[] clientDataHash = hash(clientDataJSON);

        byte[] signedData = ByteBuffer.allocate(authenticatorData.length + clientDataHash.length).put(authenticatorData).put(clientDataHash).array();

        Signature sig = Signature.getInstance(signAlgo);
        sig.initSign(keyPair.getPrivate());
        sig.update(signedData);
        return sig.sign();
    }

    public static AttestationCertificatePath generateCertPath(KeyPair pair, String signAlgo) {
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


            return new AttestationCertificatePath(Arrays.asList(x509));
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }


    }
}