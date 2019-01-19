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

package com.webauthn4j.converter.jackson.serializer;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.response.attestation.statement.TPMSAttest;
import com.webauthn4j.response.attestation.statement.TPMSCertifyInfo;
import com.webauthn4j.response.attestation.statement.TPMSClockInfo;
import com.webauthn4j.response.attestation.statement.TPMUAttest;
import com.webauthn4j.util.UnsignedNumberUtil;
import com.webauthn4j.util.exception.NotImplementedException;

import java.io.IOException;
import java.nio.ByteBuffer;

public class TPMSAttestSerializer extends StdSerializer<TPMSAttest> {
    public TPMSAttestSerializer() {
        super(TPMSAttest.class);
    }

    @Override
    public void serialize(TPMSAttest value, JsonGenerator gen, SerializerProvider provider) throws IOException {
        gen.writeBinary(value.getMagic().getValue());
        gen.writeBinary(value.getType().getValue());
        writeSizedArray(gen, value.getQualifiedSigner());
        writeSizedArray(gen, value.getExtraData());
        writeSizedArray(gen, serializeTPMSClockInfo(value.getClockInfo()));
        gen.writeBinary(UnsignedNumberUtil.toBytes(value.getFirmwareVersion()));
        gen.writeBinary(serializeTPMUAttest(value.getAttested()));
    }

    private void writeSizedArray(JsonGenerator gen, byte[] value) throws IOException {
        if(value.length > UnsignedNumberUtil.UNSIGNED_SHORT_MAX){
            throw new DataConversionException("too large data to write");
        }
        gen.writeBinary(UnsignedNumberUtil.toBytes(value.length));
        gen.writeBinary(value);
    }

    private byte[] serializeTPMSClockInfo(TPMSClockInfo clockInfo){
        ByteBuffer buffer = ByteBuffer.allocate(0);
        buffer.put(UnsignedNumberUtil.toBytes(clockInfo.getClock()));
        buffer.put(UnsignedNumberUtil.toBytes(clockInfo.getResetCount()));
        buffer.put(UnsignedNumberUtil.toBytes(clockInfo.getRestartCount()));
        buffer.put(clockInfo.isSafe() ? (byte)0x01 : (byte)0x00);
        return buffer.array();
    }

    private byte[] serializeTPMUAttest(TPMUAttest attested){
        if(attested instanceof TPMSCertifyInfo){
            TPMSCertifyInfo certifyInfo = (TPMSCertifyInfo)attested;
            ByteBuffer buffer = ByteBuffer.allocate(0);
            buffer.put(UnsignedNumberUtil.toBytes(certifyInfo.getName().length));
            buffer.put(certifyInfo.getName());
            buffer.put(UnsignedNumberUtil.toBytes(certifyInfo.getQualifiedName().length));
            buffer.put(certifyInfo.getQualifiedName());
            return buffer.array();
        }
        else {
            throw new NotImplementedException();
        }
    }
}
