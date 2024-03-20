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

import com.webauthn4j.util.UnsignedNumberUtil;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Objects;

public class TPMSClockInfo {

    private final BigInteger clock;
    private final long resetCount;
    private final long restartCount;
    private final boolean safe;

    public TPMSClockInfo(@NonNull BigInteger clock, long resetCount, long restartCount, boolean safe) {
        this.clock = clock;
        this.resetCount = resetCount;
        this.restartCount = restartCount;
        this.safe = safe;
    }

    public @NonNull BigInteger getClock() {
        return clock;
    }

    public long getResetCount() {
        return resetCount;
    }

    public long getRestartCount() {
        return restartCount;
    }

    public boolean isSafe() {
        return safe;
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TPMSClockInfo that = (TPMSClockInfo) o;
        return resetCount == that.resetCount &&
                restartCount == that.restartCount &&
                safe == that.safe &&
                Objects.equals(clock, that.clock);
    }

    @Override
    public int hashCode() {

        return Objects.hash(clock, resetCount, restartCount, safe);
    }

    public byte[] getBytes() {
        ByteBuffer buffer = ByteBuffer.allocate(17);
        buffer.put(UnsignedNumberUtil.toBytes(getClock()));
        buffer.put(UnsignedNumberUtil.toBytes(getResetCount()));
        buffer.put(UnsignedNumberUtil.toBytes(getRestartCount()));
        buffer.put(isSafe() ? (byte) 0x01 : (byte) 0x00);
        return buffer.array();
    }
}
