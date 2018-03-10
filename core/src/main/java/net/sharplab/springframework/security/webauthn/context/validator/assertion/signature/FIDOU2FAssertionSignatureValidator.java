package net.sharplab.springframework.security.webauthn.context.validator.assertion.signature;

import net.sharplab.springframework.security.webauthn.attestation.authenticator.WebAuthnAuthenticatorData;
import net.sharplab.springframework.security.webauthn.client.ClientData;
import net.sharplab.springframework.security.webauthn.context.WebAuthnAuthenticationContext;
import net.sharplab.springframework.security.webauthn.util.MessageDigestUtil;
import net.sharplab.springframework.security.webauthn.util.UnsignedNumberUtil;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * FIDOU2FAssertionSignatureValidator
 */
public class FIDOU2FAssertionSignatureValidator extends AbstractAssertionSignatureValidator {

    @Override
    public boolean supports(String format) {
        return "fido-u2f".equals(format);
    }

    protected byte[] getSignedData(WebAuthnAuthenticationContext webAuthnAuthenticationContext) {
        WebAuthnAuthenticatorData authenticatorData = webAuthnAuthenticationContext.getAuthenticatorData();
        ClientData clientData = webAuthnAuthenticationContext.getClientData();
        String clientDataJson = webAuthnAuthenticationContext.getClientDataJson();
        String appId = clientData.getOrigin().getServerName();
        MessageDigest messageDigest = MessageDigestUtil.createMessageDigest("S256");


        byte[] appIdBytes = appId.getBytes(StandardCharsets.UTF_8);
        byte[] appParam = messageDigest.digest(appIdBytes);
        byte flags = authenticatorData.getFlags();
        byte[] counter = UnsignedNumberUtil.toBytes(authenticatorData.getCounter());
        byte[] clientDataJsonBytes = clientDataJson.getBytes(StandardCharsets.UTF_8);
        byte[] challengeParameter = messageDigest.digest(clientDataJsonBytes);

        byte[] data = new byte[32 + 1 + 4 + 32];
        System.arraycopy(appParam, 0, data, 0, 32);
        data[32] = flags;
        System.arraycopy(counter, 0, data, 33, 4);
        System.arraycopy(challengeParameter, 0, data, 37, 32);
        return data;
    }


}
