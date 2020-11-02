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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.webauthn4j.util.ArrayUtil;

import java.io.Serializable;

public class Response implements Serializable {

    @JsonProperty
    private final String nonce;
    @JsonProperty
    private final long timestampMs; //TODO must not be primitive
    @JsonProperty
    private final String apkPackageName;
    @JsonProperty
    private final String[] apkCertificateDigestSha256;
    @JsonProperty
    private final String apkDigestSha256;
    @JsonProperty
    private final boolean ctsProfileMatch;
    @JsonProperty
    private final boolean basicIntegrity;
    @JsonProperty
    private final String advice;

    @JsonCreator
    public Response(
            @JsonProperty("nonce") String nonce,
            @JsonProperty("timestampMs") long timestampMs,
            @JsonProperty("apkPackageName") String apkPackageName,
            @JsonProperty("apkCertificateDigestSha256") String[] apkCertificateDigestSha256,
            @JsonProperty("apkDigestSha256") String apkDigestSha256,
            @JsonProperty("ctsProfileMatch") boolean ctsProfileMatch,
            @JsonProperty("basicIntegrity") boolean basicIntegrity,
            @JsonProperty("advice") String advice) {
        this.nonce = nonce;
        this.timestampMs = timestampMs;
        this.apkPackageName = apkPackageName;
        this.apkCertificateDigestSha256 = apkCertificateDigestSha256;
        this.apkDigestSha256 = apkDigestSha256;
        this.ctsProfileMatch = ctsProfileMatch;
        this.basicIntegrity = basicIntegrity;
        this.advice = advice;
    }

    public String getNonce() {
        return nonce;
    }

    public long getTimestampMs() {
        return timestampMs;
    }

    public String getApkPackageName() {
        return apkPackageName;
    }

    public String[] getApkCertificateDigestSha256() {
        return ArrayUtil.clone(apkCertificateDigestSha256);
    }

    public String getApkDigestSha256() {
        return apkDigestSha256;
    }

    public boolean isCtsProfileMatch() {
        return ctsProfileMatch;
    }

    public boolean isBasicIntegrity() {
        return basicIntegrity;
    }

    public String getAdvice() {
        return advice;
    }
}
