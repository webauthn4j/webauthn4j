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

package com.webauthn4j.response.attestation.statement;

import java.util.Arrays;

public class ECCParam implements TPMUPublicId {

    private byte[] x;
    private byte[] y;

    public ECCParam(byte[] x, byte[] y) {
        this.x = x;
        this.y = y;
    }

    public byte[] getX() {
        return x;
    }

    public byte[] getY() {
        return y;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ECCParam eccParam = (ECCParam) o;
        return Arrays.equals(x, eccParam.x) &&
                Arrays.equals(y, eccParam.y);
    }

    @Override
    public int hashCode() {

        int result = Arrays.hashCode(x);
        result = 31 * result + Arrays.hashCode(y);
        return result;
    }
}
