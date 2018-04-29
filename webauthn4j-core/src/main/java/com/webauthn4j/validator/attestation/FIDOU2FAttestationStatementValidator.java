package com.webauthn4j.validator.attestation;

import com.webauthn4j.attestation.AttestationObject;
import com.webauthn4j.attestation.statement.FIDOU2FAttestationStatement;
import com.webauthn4j.attestation.statement.AttestationStatement;
import com.webauthn4j.validator.RegistrationObject;
import com.webauthn4j.validator.attestation.trustworthiness.self.SelfAttestationTrustworthinessValidator;
import com.webauthn4j.validator.exception.BadSignatureException;
import com.webauthn4j.util.exception.NotImplementedException;
import com.webauthn4j.util.MessageDigestUtil;
import sun.security.ec.ECPublicKeyImpl;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;

public class FIDOU2FAttestationStatementValidator extends AbstractAttestationStatementValidator {

    private SelfAttestationTrustworthinessValidator selfAttestationTrustworthinessValidator;

    public FIDOU2FAttestationStatementValidator(SelfAttestationTrustworthinessValidator selfAttestationTrustworthinessValidator) {
        this.selfAttestationTrustworthinessValidator = selfAttestationTrustworthinessValidator;
    }

    @Override
    protected void validateSignature(RegistrationObject registrationObject) {
        FIDOU2FAttestationStatement attestationStatement = (FIDOU2FAttestationStatement) registrationObject.getAttestationObject().getAttestationStatement();

        byte[] signedData = getSignedData(registrationObject);
        byte[] signature = attestationStatement.getSig();
        PublicKey publicKey = getPublicKey(attestationStatement);

        try {
            Signature verifier = Signature.getInstance("SHA256withECDSA");
            verifier.initVerify(publicKey);
            verifier.update(signedData);
            if (verifier.verify(signature)) {
                return;
            }
            throw new BadSignatureException("Bad signature");
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
            throw new BadSignatureException("Bad signature", e);
        }
    }

    @Override
    protected void validateTrustworthiness(RegistrationObject registrationObject) {
        AttestationStatement attestationStatement = registrationObject.getAttestationObject().getAttestationStatement();
        switch (attestationStatement.getAttestationType()) {
            case Self:
                selfAttestationTrustworthinessValidator.validate(attestationStatement);
                break;
            case None:
                break;
            default:
                throw new NotImplementedException(); // TODO: To be implemented
        }
    }

    @Override
    public boolean supports(RegistrationObject registrationObject) {
        AttestationStatement attestationStatement = registrationObject.getAttestationObject().getAttestationStatement();
        return FIDOU2FAttestationStatement.class.isAssignableFrom(attestationStatement.getClass());
    }


    private byte[] getSignedData(RegistrationObject registrationObject) {

        String rpId = registrationObject.getRelyingParty().getRpId();
        MessageDigest messageDigest = MessageDigestUtil.createSHA256();

        AttestationObject attestationObject = registrationObject.getAttestationObject();
        ECPublicKeyImpl userPublicKey = (ECPublicKeyImpl) attestationObject.getAuthenticatorData().getAttestedCredentialData().getCredentialPublicKey().getPublicKey();

        byte[] rpIdBytes = rpId.getBytes(StandardCharsets.UTF_8);

        byte[] clientDataJsonBytes = registrationObject.getCollectedClientDataBytes();

        byte[] applicationParameter = messageDigest.digest(rpIdBytes);
        byte[] challengeParameter = messageDigest.digest(clientDataJsonBytes);
        byte[] keyHandle = attestationObject.getAuthenticatorData().getAttestedCredentialData().getCredentialId();
        byte[] userPublicKeyBytes = userPublicKey.getEncodedPublicValue();

        ByteBuffer byteBuffer = ByteBuffer.allocate(1 + 32 + 32 + keyHandle.length + 65);
        byteBuffer.put((byte) 0x00); //RFU
        byteBuffer.put(applicationParameter);
        byteBuffer.put(challengeParameter);
        byteBuffer.put(keyHandle);
        byteBuffer.put(userPublicKeyBytes);
        return byteBuffer.array();
    }

    private PublicKey getPublicKey(FIDOU2FAttestationStatement attestationStatement) {
        Certificate cert = attestationStatement.getX5c().getCertificates().get(0);
        return cert.getPublicKey();
    }

}
