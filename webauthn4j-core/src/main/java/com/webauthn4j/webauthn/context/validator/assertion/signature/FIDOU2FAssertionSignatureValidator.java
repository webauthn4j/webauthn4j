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

package com.webauthn4j.webauthn.context.validator.assertion.signature;

import com.webauthn4j.webauthn.attestation.authenticator.WebAuthnAuthenticatorData;
import com.webauthn4j.webauthn.client.CollectedClientData;
import com.webauthn4j.webauthn.context.WebAuthnAuthenticationContext;
import com.webauthn4j.webauthn.util.MessageDigestUtil;
import com.webauthn4j.webauthn.util.UnsignedNumberUtil;

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
        CollectedClientData collectedClientData = webAuthnAuthenticationContext.getCollectedClientData();
        String clientDataJson = webAuthnAuthenticationContext.getClientDataJson();
        String appId = collectedClientData.getOrigin().getServerName();
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
