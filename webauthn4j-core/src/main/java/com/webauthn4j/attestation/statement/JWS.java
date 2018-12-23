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

package com.webauthn4j.attestation.statement;

import com.webauthn4j.util.SignatureUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.InvalidKeyException;
import java.security.Signature;
import java.security.SignatureException;

public class JWS {

    Logger logger = LoggerFactory.getLogger(JWS.class);

    private JWSHeader header;

    private Response payload;

    private byte[] signature;

    private String headerString;
    private String payloadString;

    public JWS(JWSHeader header, String headerString, Response payload, String payloadString, byte[] signature) {
        this.header = header;
        this.payload = payload;
        this.signature = signature;
        this.headerString = headerString;
        this.payloadString = payloadString;
    }

    public JWSHeader getHeader() {
        return header;
    }

    public Response getPayload() {
        return payload;
    }

    public byte[] getSignature() {
        return signature;
    }

    public boolean isValidSignature(){
        String signedData = headerString + "." + payloadString;
        try {
            Signature signatureObj = SignatureUtil.createSignature(header.getAlg());
            signatureObj.initVerify(header.getX5c().getEndEntityAttestationCertificate().getCertificate().getPublicKey());
            signatureObj.update(signedData.getBytes());
            return signatureObj.verify(signature);
        } catch (SignatureException | InvalidKeyException e) {
            logger.debug("Signature verification failed", e);
            return false;
        }
    }
}
