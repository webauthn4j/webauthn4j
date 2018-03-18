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

package net.sharplab.springframework.security.webauthn.context.validator.attestation.signature;

import net.sharplab.springframework.security.webauthn.attestation.WebAuthnAttestationObject;
import net.sharplab.springframework.security.webauthn.attestation.statement.FIDOU2FAttestationStatement;
import net.sharplab.springframework.security.webauthn.context.WebAuthnRegistrationContext;
import net.sharplab.springframework.security.webauthn.exception.BadSignatureException;
import net.sharplab.springframework.security.webauthn.util.MessageDigestUtil;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.core.SpringSecurityMessageSource;
import sun.security.ec.ECPublicKeyImpl;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;

/**
 * Validates {@link FIDOU2FAttestationStatement}'s signature
 */
public class FIDOU2FAttestationStatementSignatureValidator implements AttestationStatementSignatureValidator {

    protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

    @Override
    public void validate(WebAuthnRegistrationContext registrationContext) {
        FIDOU2FAttestationStatement attestationStatement = (FIDOU2FAttestationStatement) registrationContext.getAttestationObject().getAttestationStatement();

        byte[] signedData = getSignedData(registrationContext); //TODO
        byte[] signature = attestationStatement.getSig();
        PublicKey publicKey = getPublicKey(attestationStatement);

        try {
            Signature verifier = Signature.getInstance("SHA256withECDSA");
            verifier.initVerify(publicKey);
            verifier.update(signedData);
            if (verifier.verify(signature)) {
                return;
            }
            throw new BadSignatureException(messages.getMessage("FIDOU2FAttestationStatementSignatureValidator.BadSignature", "Bad signature"));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        } catch (SignatureException e) {
            throw new IllegalArgumentException(e); //TODO
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e); //TODO
        }
    }

    @Override
    public boolean supports(String format) {
        return FIDOU2FAttestationStatement.FORMAT.equals(format);
    }

    private byte[] getSignedData(WebAuthnRegistrationContext registrationContext) {

        String appId = "localhost"; //TODO
        MessageDigest messageDigest = MessageDigestUtil.createMessageDigest("S256");

        WebAuthnAttestationObject attestationObject = registrationContext.getAttestationObject();
        ECPublicKeyImpl userPublicKey = (ECPublicKeyImpl) attestationObject.getAuthenticatorData().getAttestationData().getCredentialPublicKey().getPublicKey();

        byte[] clientDataJsonBytes = registrationContext.getClientDataBytes();
        byte[] clientDataHash = messageDigest.digest(clientDataJsonBytes);


        byte[] appIdBytes = appId.getBytes(StandardCharsets.UTF_8);
        byte[] applicationParameter = messageDigest.digest(appIdBytes);
        byte[] challengeParameter = clientDataHash;
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
