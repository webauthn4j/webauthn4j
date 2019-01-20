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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public class TPMSAttestSerializer extends StdSerializer<TPMSAttest> {
    public TPMSAttestSerializer() {
        super(TPMSAttest.class);
    }

    @Override
    public void serialize(TPMSAttest value, JsonGenerator gen, SerializerProvider provider) throws IOException {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        stream.write(value.getMagic().getValue());
        stream.write(value.getType().getValue());
        writeSizedArray(value.getQualifiedSigner(), stream);
        writeSizedArray(value.getExtraData(), stream);
        writeTPMSClockInfo(value.getClockInfo(), stream);
        stream.write(UnsignedNumberUtil.toBytes(value.getFirmwareVersion()));
        writeTPMUAttest(value.getAttested(), stream);

        gen.writeBinary(stream.toByteArray());
    }

    private void writeTPMSClockInfo(TPMSClockInfo clockInfo, OutputStream stream) throws IOException {
        stream.write(UnsignedNumberUtil.toBytes(clockInfo.getClock()));
        stream.write(UnsignedNumberUtil.toBytes(clockInfo.getResetCount()));
        stream.write(UnsignedNumberUtil.toBytes(clockInfo.getRestartCount()));
        stream.write(clockInfo.isSafe() ? (byte)0x01 : (byte)0x00);
    }

    private void writeTPMUAttest(TPMUAttest attested, OutputStream stream) throws IOException {
        if(attested instanceof TPMSCertifyInfo){
            TPMSCertifyInfo certifyInfo = (TPMSCertifyInfo)attested;

            writeSizedArray(certifyInfo.getName(), stream);
            writeSizedArray(certifyInfo.getQualifiedName(), stream);
        }
        else {
            throw new NotImplementedException();
        }
    }

    private void writeSizedArray(byte[] value, OutputStream stream) throws IOException {
        if(value.length > UnsignedNumberUtil.UNSIGNED_SHORT_MAX){
            throw new DataConversionException("too large data to write");
        }
        stream.write(UnsignedNumberUtil.toBytes(value.length));
        stream.write(value);
    }
}
