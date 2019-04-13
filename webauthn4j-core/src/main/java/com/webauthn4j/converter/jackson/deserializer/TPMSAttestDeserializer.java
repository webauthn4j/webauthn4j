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
import com.webauthn4j.data.attestation.statement.*;
import com.webauthn4j.util.UnsignedNumberUtil;
import com.webauthn4j.util.exception.NotImplementedException;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;

/**
 * Jackson Deserializer for {@link TPMSAttest}
 */
public class TPMSAttestDeserializer extends StdDeserializer<TPMSAttest> {

    public TPMSAttestDeserializer() {
        super(TPMSAttest.class);
    }

    @Override
    public TPMSAttest deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
        byte[] value = p.getBinaryValue();
        ByteBuffer buffer = ByteBuffer.wrap(value);
        byte[] magicBytes = new byte[4];
        buffer.get(magicBytes);
        TPMGenerated magic = TPMGenerated.create(magicBytes);
        byte[] typeBytes = new byte[2];
        buffer.get(typeBytes);
        TPMISTAttest type = TPMISTAttest.create(typeBytes);
        int qualifiedSignerSize = UnsignedNumberUtil.getUnsignedShort(buffer);
        byte[] qualifiedSigner = new byte[qualifiedSignerSize];
        buffer.get(qualifiedSigner);
        int extraDataSize = UnsignedNumberUtil.getUnsignedShort(buffer);
        byte[] extraData = new byte[extraDataSize];
        buffer.get(extraData);
        TPMSClockInfo clock = extractClockInfo(buffer);
        BigInteger firmwareVersion = UnsignedNumberUtil.getUnsignedLong(buffer);
        TPMUAttest attested = extractTPMUAttest(type, buffer);
        if(buffer.remaining() > 0){
            throw new InvalidFormatException(p, "input byte array contains surplus data", value, TPMTPublic.class);
        }

        return new TPMSAttest(magic, type, qualifiedSigner, extraData, clock, firmwareVersion, attested);
    }

    private TPMSClockInfo extractClockInfo(ByteBuffer buffer){
        BigInteger clock = UnsignedNumberUtil.getUnsignedLong(buffer);
        long resetCount = UnsignedNumberUtil.getUnsignedInt(buffer);
        long restartCount = UnsignedNumberUtil.getUnsignedInt(buffer);
        boolean safe = buffer.get() != 0;
        return new TPMSClockInfo(clock, resetCount, restartCount, safe);
    }

    private TPMUAttest extractTPMUAttest(TPMISTAttest type, ByteBuffer buffer) {
        if(type != TPMISTAttest.TPM_ST_ATTEST_CERTIFY){
            throw new NotImplementedException();
        }

        int nameSize = UnsignedNumberUtil.getUnsignedShort(buffer);
        TPMTHA name = extractTPMTHA(buffer, nameSize - 2);
        int qualifiedNameSize = UnsignedNumberUtil.getUnsignedShort(buffer);
        TPMTHA qualifiedName = extractTPMTHA(buffer, qualifiedNameSize - 2);

        return new TPMSCertifyInfo(name, qualifiedName);
    }

    private TPMTHA extractTPMTHA(ByteBuffer buffer, int digestLength) {
        TPMIAlgHash hashAlg = TPMIAlgHash.create(UnsignedNumberUtil.getUnsignedShort(buffer));
        byte[] digest = new byte[digestLength];
        buffer.get(digest);
        return new TPMTHA(hashAlg, digest);
    }
}
