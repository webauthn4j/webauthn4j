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

package com.webauthn4j.data.attestation.statement;

import com.webauthn4j.util.ArrayUtil;
import com.webauthn4j.util.UnsignedNumberUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Objects;

public class TPMSAttest {

    private final TPMGenerated magic;
    private final TPMISTAttest type;
    private final byte[] qualifiedSigner;
    private final byte[] extraData;
    private final TPMSClockInfo clockInfo;
    private final BigInteger firmwareVersion;
    private final TPMUAttest attested;

    public TPMSAttest(
            @NotNull TPMGenerated magic,
            @NotNull TPMISTAttest type,
            @NotNull byte[] qualifiedSigner,
            @NotNull byte[] extraData,
            @NotNull TPMSClockInfo clockInfo,
            @NotNull BigInteger firmwareVersion,
            @NotNull TPMUAttest attested) {
        this.magic = magic;
        this.type = type;
        this.qualifiedSigner = qualifiedSigner;
        this.extraData = extraData;
        this.clockInfo = clockInfo;
        this.firmwareVersion = firmwareVersion;
        this.attested = attested;
    }

    public @NotNull TPMGenerated getMagic() {
        return magic;
    }

    public @NotNull TPMISTAttest getType() {
        return type;
    }

    public @NotNull byte[] getQualifiedSigner() {
        return ArrayUtil.clone(qualifiedSigner);
    }

    public @NotNull byte[] getExtraData() {
        return ArrayUtil.clone(extraData);
    }

    public @NotNull TPMSClockInfo getClockInfo() {
        return clockInfo;
    }

    public @NotNull BigInteger getFirmwareVersion() {
        return firmwareVersion;
    }

    public @NotNull TPMUAttest getAttested() {
        return attested;
    }

    public @NotNull byte[] getBytes() {
        try {
            ByteArrayOutputStream stream = new ByteArrayOutputStream();
            stream.write(getMagic().getValue());
            stream.write(getType().getValue());
            TPMUtil.writeSizedArray(stream, getQualifiedSigner());
            TPMUtil.writeSizedArray(stream, getExtraData());
            stream.write(getClockInfo().getBytes());
            stream.write(UnsignedNumberUtil.toBytes(getFirmwareVersion()));
            stream.write(getAttested().getBytes());
            return stream.toByteArray();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TPMSAttest that = (TPMSAttest) o;
        return magic == that.magic &&
                type == that.type &&
                Arrays.equals(qualifiedSigner, that.qualifiedSigner) &&
                Arrays.equals(extraData, that.extraData) &&
                Objects.equals(clockInfo, that.clockInfo) &&
                Objects.equals(firmwareVersion, that.firmwareVersion) &&
                Objects.equals(attested, that.attested);
    }

    @Override
    public int hashCode() {

        int result = Objects.hash(magic, type, clockInfo, firmwareVersion, attested);
        result = 31 * result + Arrays.hashCode(qualifiedSigner);
        result = 31 * result + Arrays.hashCode(extraData);
        return result;
    }
}
