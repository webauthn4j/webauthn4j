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
import com.webauthn4j.response.attestation.statement.*;
import com.webauthn4j.util.UnsignedNumberUtil;
import com.webauthn4j.util.exception.NotImplementedException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public class TPMTPublicSerializer extends StdSerializer<TPMTPublic> {

    public TPMTPublicSerializer() {
        super(TPMTPublic.class);
    }

    @Override
    public void serialize(TPMTPublic value, JsonGenerator gen, SerializerProvider provider) throws IOException {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        TPMIAlgPublic type = value.getType();
        int typeValue = type.getValue();
        stream.write(UnsignedNumberUtil.toBytes(typeValue));
        int nameAlgValue = value.getNameAlg();
        stream.write(UnsignedNumberUtil.toBytes(nameAlgValue));
        writeTPMAObject(value.getObjectAttributes(), stream);
        writeSizedArray(value.getAuthPolicy(), stream);
        writeTPMUPublicParms(value.getParameters(), stream);
        writeTPMUPublicId(value.getUnique(), stream);

        gen.writeBinary(stream.toByteArray());
    }

    private void writeTPMAObject(TPMAObject objectAttributes, OutputStream stream) throws IOException {
        stream.write(objectAttributes.getBytes());
    }

    private void writeTPMUPublicParms(TPMUPublicParms parameters, OutputStream stream) throws IOException {
        if(parameters instanceof TPMSRSAParms){
            stream.write(parameters.getBytes());
        }
        else if(parameters instanceof TPMSECCParms){
            stream.write(parameters.getBytes());
        }
        else {
            throw new NotImplementedException();
        }
    }

    private void writeTPMUPublicId(TPMUPublicId unique, OutputStream stream) throws IOException {
        if(unique instanceof RSAParam){
            RSAParam rsaParam = (RSAParam) unique;
            stream.write(UnsignedNumberUtil.toBytes(rsaParam.getN().length));
            stream.write(rsaParam.getN());
        }
        else if(unique instanceof ECCParam){
            ECCParam eccParam = (ECCParam) unique;
            stream.write(UnsignedNumberUtil.toBytes(eccParam.getX().length));
            stream.write(eccParam.getX());
            stream.write(UnsignedNumberUtil.toBytes(eccParam.getY().length));
            stream.write(eccParam.getY());
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
