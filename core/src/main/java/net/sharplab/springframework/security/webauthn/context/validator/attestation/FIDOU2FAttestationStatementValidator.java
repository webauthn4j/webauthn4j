package net.sharplab.springframework.security.webauthn.context.validator.attestation;

import net.sharplab.springframework.security.webauthn.attestation.WebAuthnAttestationObject;
import net.sharplab.springframework.security.webauthn.attestation.statement.FIDOU2FAttestationStatement;
import net.sharplab.springframework.security.webauthn.attestation.statement.WebAuthnAttestationStatement;
import net.sharplab.springframework.security.webauthn.context.WebAuthnRegistrationContext;
import net.sharplab.springframework.security.webauthn.context.validator.attestation.trustworthiness.self.SelfAttestationTrustworthinessValidator;
import net.sharplab.springframework.security.webauthn.exception.BadSignatureException;
import net.sharplab.springframework.security.webauthn.exception.NotImplementedException;
import net.sharplab.springframework.security.webauthn.util.MessageDigestUtil;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.core.SpringSecurityMessageSource;
import sun.security.ec.ECPublicKeyImpl;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;

public class FIDOU2FAttestationStatementValidator extends AbstractAttestationStatementValidator {

    protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

    private SelfAttestationTrustworthinessValidator selfAttestationTrustworthinessValidator;

    public FIDOU2FAttestationStatementValidator(SelfAttestationTrustworthinessValidator selfAttestationTrustworthinessValidator){
        this.selfAttestationTrustworthinessValidator = selfAttestationTrustworthinessValidator;
    }

    @Override
    protected void validateSignature(WebAuthnRegistrationContext registrationContext) {
        FIDOU2FAttestationStatement attestationStatement = (FIDOU2FAttestationStatement) registrationContext.getAttestationObject().getAttestationStatement();

        byte[] signedData = getSignedData(registrationContext);
        byte[] signature = attestationStatement.getSig();
        PublicKey publicKey = getPublicKey(attestationStatement);

        try {
            Signature verifier = Signature.getInstance("SHA256withECDSA");
            verifier.initVerify(publicKey);
            verifier.update(signedData);
            if (verifier.verify(signature)) {
                return;
            }
            throw new BadSignatureException(messages.getMessage("FIDOU2FAttestationStatementValidator.BadSignature", "Bad signature"));
        }
        catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
            throw new BadSignatureException(messages.getMessage("FIDOU2FAttestationStatementValidator.BadSignature", "Bad signature"), e);
        }
    }

    @Override
    protected void validateTrustworthiness(WebAuthnRegistrationContext registrationContext) {
        WebAuthnAttestationStatement attestationStatement = registrationContext.getAttestationObject().getAttestationStatement();
        switch (attestationStatement.getAttestationType()){
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
    public boolean supports(WebAuthnRegistrationContext registrationContext) {
        WebAuthnAttestationStatement attestationStatement = registrationContext.getAttestationObject().getAttestationStatement();
        return FIDOU2FAttestationStatement.class.isAssignableFrom(attestationStatement.getClass());
    }


    private byte[] getSignedData(WebAuthnRegistrationContext registrationContext) {

        String rpId = registrationContext.getRelyingParty().getRpId();
        MessageDigest messageDigest = MessageDigestUtil.createMessageDigest("S256");

        WebAuthnAttestationObject attestationObject = registrationContext.getAttestationObject();
        ECPublicKeyImpl userPublicKey = (ECPublicKeyImpl) attestationObject.getAuthenticatorData().getAttestationData().getCredentialPublicKey().getPublicKey();

        byte[] rpIdBytes = rpId.getBytes(StandardCharsets.UTF_8);

        byte[] clientDataJsonBytes = registrationContext.getClientDataBytes();

        byte[] applicationParameter = messageDigest.digest(rpIdBytes);
        byte[] challengeParameter = messageDigest.digest(clientDataJsonBytes);
        byte[] keyHandle = attestationObject.getAuthenticatorData().getAttestationData().getCredentialId();
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
