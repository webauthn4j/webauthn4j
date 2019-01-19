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

public class TPMSCertifyInfo implements TPMUAttest {

    private byte[] name;
    private byte[] qualifiedName;

    public TPMSCertifyInfo(byte[] name, byte[] qualifiedName) {
        this.name = name;
        this.qualifiedName = qualifiedName;
    }

    public byte[] getName() {
        return name;
    }

    public byte[] getQualifiedName() {
        return qualifiedName;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TPMSCertifyInfo that = (TPMSCertifyInfo) o;
        return Arrays.equals(name, that.name) &&
                Arrays.equals(qualifiedName, that.qualifiedName);
    }

    @Override
    public int hashCode() {

        int result = Arrays.hashCode(name);
        result = 31 * result + Arrays.hashCode(qualifiedName);
        return result;
    }
}
