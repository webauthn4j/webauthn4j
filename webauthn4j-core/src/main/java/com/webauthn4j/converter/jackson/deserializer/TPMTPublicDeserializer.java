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

package com.webauthn4j.converter.jackson.deserializer;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import com.webauthn4j.response.attestation.statement.*;
import com.webauthn4j.util.UnsignedNumberUtil;
import com.webauthn4j.util.exception.NotImplementedException;

import java.io.IOException;
import java.nio.ByteBuffer;

public class TPMTPublicDeserializer extends StdDeserializer<TPMTPublic> {

    public TPMTPublicDeserializer() {
        super(TPMTPublic.class);
    }

    @Override
    public TPMTPublic deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
        byte[] value = p.getBinaryValue();
        ByteBuffer buffer = ByteBuffer.wrap(value);

        int typeValue = UnsignedNumberUtil.getUnsignedShort(buffer);
        TPMIAlgPublic type = TPMIAlgPublic.create(typeValue);
        int nameAlgValue = UnsignedNumberUtil.getUnsignedShort(buffer);
        TPMAObject objectAttributes = extractTPMAObject(buffer);
        int authPolicySize = UnsignedNumberUtil.getUnsignedShort(buffer);
        byte[] authPolicy = new byte[authPolicySize];
        buffer.get(authPolicy);
        TPMUPublicParms parameters = extractTPMUPublicParms(type, buffer);
        TPMUPublicId unique = extractTPMUPublicId(type, buffer);
        if(buffer.remaining() > 0){
            throw new InvalidFormatException(p, "input byte array contains surplus data", value, TPMTPublic.class);
        }

        return new TPMTPublic(type, nameAlgValue, objectAttributes, authPolicy, parameters, unique);
    }

    private TPMAObject extractTPMAObject(ByteBuffer buffer){
        int value = buffer.getInt();
        return new TPMAObject(value);
    }

    private TPMUPublicParms extractTPMUPublicParms(TPMIAlgPublic type, ByteBuffer buffer){
        switch (type){
            case TPM_ALG_RSA:
                return extractTPMSRSAParms(buffer);
            case TPM_ALG_ECC:
                return extractTPMSECCParms(buffer);
            default:
                throw new NotImplementedException();
        }
    }

    private TPMSRSAParms extractTPMSRSAParms(ByteBuffer buffer){
        byte[] symmetric = new byte[2];
        buffer.get(symmetric);
        byte[] scheme = new byte[2];
        buffer.get(scheme);
        byte[] keyBits = new byte[2];
        buffer.get(keyBits);
        byte[] exponent = new byte[4];
        buffer.get(exponent);
        return new TPMSRSAParms(symmetric, scheme, keyBits, exponent);
    }

    private TPMSECCParms extractTPMSECCParms(ByteBuffer buffer){
        byte[] symmetric = new byte[2];
        buffer.get(symmetric);
        byte[] scheme = new byte[2];
        buffer.get(scheme);
        byte[] curveId = new byte[2];
        buffer.get(curveId);
        byte[] kdf = new byte[2];
        buffer.get(kdf);
        return new TPMSECCParms(symmetric, scheme, curveId, kdf);
    }

    private TPMUPublicId extractTPMUPublicId(TPMIAlgPublic type, ByteBuffer buffer){
        if(type == TPMIAlgPublic.TPM_ALG_RSA){
            int nSize = UnsignedNumberUtil.getUnsignedShort(buffer);
            byte[] n = new byte[nSize];
            buffer.get(n);
            return new RSAParam(n);
        }
        else if(type == TPMIAlgPublic.TPM_ALG_ECC) {
            int xSize = UnsignedNumberUtil.getUnsignedShort(buffer);
            byte[] x = new byte[xSize];
            buffer.get(x);
            int ySize = UnsignedNumberUtil.getUnsignedShort(buffer);
            byte[] y = new byte[ySize];
            buffer.get(y);
            return new ECCParam(x, y);
        }
        else {
            throw new NotImplementedException();
        }
    }


}
