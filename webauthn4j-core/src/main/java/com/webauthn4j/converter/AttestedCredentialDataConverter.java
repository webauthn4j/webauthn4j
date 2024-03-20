/*
 * Copyright 2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webauthn4j.converter;

import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.jackson.deserializer.cbor.COSEKeyEnvelope;
import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.util.UnsignedNumberUtil;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.io.*;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.util.Arrays;

public class AttestedCredentialDataConverter {

    private static final String ATTESTED_CREDENTIAL_DATA_MUST_NOT_BE_NULL = "attestedCredentialData must not be null";

    private static final int AAGUID_LENGTH = 16;
    private static final int L_LENGTH = 2;

    private static final int AAGUID_INDEX = 0;
    private static final int L_INDEX = AAGUID_INDEX + AAGUID_LENGTH;
    private static final int CREDENTIAL_ID_INDEX = L_INDEX + L_LENGTH;

    private final CborConverter cborConverter;

    public AttestedCredentialDataConverter(@NonNull ObjectConverter objectConverter) {
        AssertUtil.notNull(objectConverter, "objectConverter must not be null");
        this.cborConverter = objectConverter.getCborConverter();
    }

    private static AttestedCredentialData createAttestedCredentialData(@NonNull AAGUID aaguid, @NonNull byte[] credentialId, @NonNull COSEKey coseKey) {
        return new AttestedCredentialData(aaguid, credentialId, coseKey);
    }

    private static void assertCoseKey(@Nullable COSEKey coseKey) {
        AssertUtil.notNull(coseKey, "coseKey must not be null");
    }

    public @NonNull byte[] convert(@NonNull AttestedCredentialData attestationData) {
        try {
            AssertUtil.notNull(attestationData, "attestationData must not be null");
            AssertUtil.notNull(attestationData.getAaguid(), "aaguid must not be null");
            AssertUtil.notNull(attestationData.getCredentialId(), "credentialId must not be null");
            assertCoseKey(attestationData.getCOSEKey());

            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            byteArrayOutputStream.write(attestationData.getAaguid().getBytes());
            byteArrayOutputStream.write(UnsignedNumberUtil.toBytes(attestationData.getCredentialId().length));
            byteArrayOutputStream.write(attestationData.getCredentialId());
            byteArrayOutputStream.write(convert(attestationData.getCOSEKey()));
            return byteArrayOutputStream.toByteArray();
        } catch (IllegalArgumentException e) {
            throw new DataConversionException(e);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public @NonNull AttestedCredentialData convert(@NonNull ByteBuffer attestedCredentialData) {
        try {
            AssertUtil.notNull(attestedCredentialData, ATTESTED_CREDENTIAL_DATA_MUST_NOT_BE_NULL);

            byte[] aaguidBytes = new byte[AAGUID_LENGTH];
            attestedCredentialData.get(aaguidBytes, 0, AAGUID_LENGTH);
            AAGUID aaguid = new AAGUID(aaguidBytes);
            int length = UnsignedNumberUtil.getUnsignedShort(attestedCredentialData);
            byte[] credentialId = new byte[length];
            attestedCredentialData.get(credentialId, 0, length);
            byte[] remaining = new byte[attestedCredentialData.remaining()];
            attestedCredentialData.get(remaining);
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(remaining);
            COSEKeyEnvelope coseKeyEnvelope = convertToCredentialPublicKey(byteArrayInputStream);
            COSEKey coseKey = coseKeyEnvelope.getCOSEKey();
            assertCoseKey(coseKey);
            AttestedCredentialData result = createAttestedCredentialData(aaguid, credentialId, coseKey);
            int extensionsBufferLength = remaining.length - coseKeyEnvelope.getLength();
            //This cast is necessary to be complied with JDK 17 when targeting JDK 8
            ((Buffer)attestedCredentialData).position(attestedCredentialData.position() - extensionsBufferLength);
            return result;
        } catch (IllegalArgumentException e) {
            throw new DataConversionException(e);
        }
    }

    public @NonNull AttestedCredentialData convert(@NonNull byte[] attestedCredentialData) {
        try {
            AssertUtil.notNull(attestedCredentialData, ATTESTED_CREDENTIAL_DATA_MUST_NOT_BE_NULL);
            return convert(ByteBuffer.wrap(attestedCredentialData));
        } catch (IllegalArgumentException e) {
            throw new DataConversionException(e);
        }
    }

    /**
     * Extract credentialId byte array from a attestedCredentialData byte array.
     *
     * @param attestedCredentialData the attestedCredentialData byte array
     * @return the extracted credentialId byte array
     */
    public @NonNull byte[] extractCredentialId(@NonNull byte[] attestedCredentialData) {
        AssertUtil.notNull(attestedCredentialData, ATTESTED_CREDENTIAL_DATA_MUST_NOT_BE_NULL);
        byte[] lengthBytes = Arrays.copyOfRange(attestedCredentialData, L_INDEX, CREDENTIAL_ID_INDEX);
        int credentialIdLength = UnsignedNumberUtil.getUnsignedShort(lengthBytes);
        return Arrays.copyOfRange(attestedCredentialData, CREDENTIAL_ID_INDEX, CREDENTIAL_ID_INDEX + credentialIdLength);
    }

    @NonNull COSEKeyEnvelope convertToCredentialPublicKey(@NonNull InputStream inputStream) {
        AssertUtil.notNull(inputStream, "inputStream must not be null");
        //noinspection ConstantConditions as input stream is not null
        return cborConverter.readValue(inputStream, COSEKeyEnvelope.class);
    }

    @NonNull byte[] convert(@NonNull COSEKey coseKey) {
        assertCoseKey(coseKey);
        return cborConverter.writeValueAsBytes(coseKey);
    }

}
