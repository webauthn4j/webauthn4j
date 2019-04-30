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

package com.webauthn4j.data.jws;

import com.webauthn4j.util.ArrayUtil;
import com.webauthn4j.util.Base64UrlUtil;
import com.webauthn4j.util.SignatureUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;

public class JWS<T extends Serializable> implements Serializable {

    transient Logger logger = LoggerFactory.getLogger(JWS.class);

    private JWSHeader header;
    private T payload;
    private byte[] signature;

    private String headerString;
    private String payloadString;

    JWS(JWSHeader header, String headerString, T payload, String payloadString, byte[] signature) {
        this.header = header;
        this.payload = payload;
        this.signature = signature;
        this.headerString = headerString;
        this.payloadString = payloadString;
    }

    public JWSHeader getHeader() {
        return header;
    }

    public T getPayload() {
        return payload;
    }

    public byte[] getSignature() {
        return ArrayUtil.clone(signature);
    }

    public boolean isValidSignature() {
        String signedData = headerString + "." + payloadString;
        try {
            Signature signatureObj = SignatureUtil.createSignature(header.getAlg().getJcaName());
            PublicKey publicKey = header.getX5c().getEndEntityAttestationCertificate().getCertificate().getPublicKey();
            signatureObj.initVerify(publicKey);
            signatureObj.update(signedData.getBytes());
            byte[] sig;
            if(publicKey instanceof ECPublicKey){
                sig = JWSSignatureUtil.convertJwsSignatureToDerSignature(signature);
            }
            else{
                sig = signature;
            }
            return signatureObj.verify(sig);
        } catch (SignatureException | InvalidKeyException e) {
            logger.debug("Signature verification failed", e);
            return false;
        }
    }

    public byte[] getBytes(){
        return toString().getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public String toString(){
        return headerString + "." + payloadString + "." + Base64UrlUtil.encodeToString(signature);
    }

}
