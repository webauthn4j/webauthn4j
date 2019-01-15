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

import java.util.Objects;

public class CertInfo {

    private Object magic;
    private Object type;
    private Object qualifiedSigner;
    private Object extraData;
    private Object clockInfo;
    private Object firmwareVersion;
    private Object attestedName;
    private Object attestedQualifiedName;

    public CertInfo(Object magic, Object type, Object qualifiedSigner, Object extraData, Object clockInfo, Object firmwareVersion, Object attestedName, Object attestedQualifiedName) {
        this.magic = magic;
        this.type = type;
        this.qualifiedSigner = qualifiedSigner;
        this.extraData = extraData;
        this.clockInfo = clockInfo;
        this.firmwareVersion = firmwareVersion;
        this.attestedName = attestedName;
        this.attestedQualifiedName = attestedQualifiedName;
    }

    public Object getMagic() {
        return magic;
    }

    public Object getType() {
        return type;
    }

    public Object getQualifiedSigner() {
        return qualifiedSigner;
    }

    public Object getExtraData() {
        return extraData;
    }

    public Object getClockInfo() {
        return clockInfo;
    }

    public Object getFirmwareVersion() {
        return firmwareVersion;
    }

    public Object getAttestedName() {
        return attestedName;
    }

    public Object getAttestedQualifiedName() {
        return attestedQualifiedName;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CertInfo certInfo = (CertInfo) o;
        return Objects.equals(magic, certInfo.magic) &&
                Objects.equals(type, certInfo.type) &&
                Objects.equals(qualifiedSigner, certInfo.qualifiedSigner) &&
                Objects.equals(extraData, certInfo.extraData) &&
                Objects.equals(clockInfo, certInfo.clockInfo) &&
                Objects.equals(firmwareVersion, certInfo.firmwareVersion) &&
                Objects.equals(attestedName, certInfo.attestedName) &&
                Objects.equals(attestedQualifiedName, certInfo.attestedQualifiedName);
    }

    @Override
    public int hashCode() {

        return Objects.hash(magic, type, qualifiedSigner, extraData, clockInfo, firmwareVersion, attestedName, attestedQualifiedName);
    }
}
