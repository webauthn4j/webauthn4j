package net.sharplab.springframework.security.webauthn.context.validator.assertion.signature;

import net.sharplab.springframework.security.webauthn.context.WebAuthnAuthenticationContext;
import net.sharplab.springframework.security.webauthn.util.MessageDigestUtil;

import java.nio.ByteBuffer;
import java.security.MessageDigest;

/**
 * WebAuthnAssertionSignatureValidator
 */
public class WebAuthnAssertionSignatureValidator extends AbstractAssertionSignatureValidator {

    @Override
    public boolean supports(String format) {
        return !"fido-u2f".equals(format);
    }

    protected byte[] getSignedData(WebAuthnAuthenticationContext webAuthnAuthenticationContext){
        String hashAlgorithm = webAuthnAuthenticationContext.getClientData().getHashAlgorithm();
        MessageDigest messageDigest = MessageDigestUtil.createMessageDigest(hashAlgorithm);
        byte[] clientDataHash = messageDigest.digest(webAuthnAuthenticationContext.getRawClientData());
        byte[] rawAuthenticatorData= webAuthnAuthenticationContext.getRawAuthenticatorData();
        return ByteBuffer.allocate(rawAuthenticatorData.length + clientDataHash.length).put(rawAuthenticatorData).put(clientDataHash).array();
    }


}
