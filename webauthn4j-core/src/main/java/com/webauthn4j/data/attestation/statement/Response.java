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
import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.Arrays;

public class Response {

    @JsonProperty
    private final String nonce;
    @JsonProperty
    private final Long timestampMs;
    @JsonProperty
    private final String apkPackageName;
    @JsonProperty
    private final String[] apkCertificateDigestSha256;
    @JsonProperty
    private final String apkDigestSha256;
    @JsonProperty
    private final Boolean ctsProfileMatch;
    @JsonProperty
    private final Boolean basicIntegrity;
    @JsonProperty
    private final String advice;
    @JsonProperty
    private final String error;

    @SuppressWarnings("java:S107")
    @JsonCreator
    public Response(
            // fields are marked as Nullable because they may be null when error field is filled
            @Nullable @JsonProperty("nonce") String nonce,
            @Nullable @JsonProperty("timestampMs") Long timestampMs,
            @Nullable @JsonProperty("apkPackageName") String apkPackageName,
            @Nullable @JsonProperty("apkCertificateDigestSha256") String[] apkCertificateDigestSha256,
            @Nullable @JsonProperty("apkDigestSha256") String apkDigestSha256,
            @Nullable @JsonProperty("ctsProfileMatch") Boolean ctsProfileMatch,
            @Nullable @JsonProperty("basicIntegrity") Boolean basicIntegrity,
            @Nullable @JsonProperty("advice") String advice,
            @Nullable @JsonProperty("error") String error) {
        this.nonce = nonce;
        this.timestampMs = timestampMs;
        this.apkPackageName = apkPackageName;
        this.apkCertificateDigestSha256 = apkCertificateDigestSha256;
        this.apkDigestSha256 = apkDigestSha256;
        this.ctsProfileMatch = ctsProfileMatch;
        this.basicIntegrity = basicIntegrity;
        this.advice = advice;
        this.error = error;
    }

    @SuppressWarnings("java:S107")
    public Response(
            @Nullable @JsonProperty("nonce") String nonce,
            @Nullable @JsonProperty("timestampMs") Long timestampMs,
            @Nullable @JsonProperty("apkPackageName") String apkPackageName,
            @Nullable @JsonProperty("apkCertificateDigestSha256") String[] apkCertificateDigestSha256,
            @Nullable @JsonProperty("apkDigestSha256") String apkDigestSha256,
            @Nullable @JsonProperty("ctsProfileMatch") Boolean ctsProfileMatch,
            @Nullable @JsonProperty("basicIntegrity") Boolean basicIntegrity,
            @Nullable @JsonProperty("advice") String advice) {
        this(nonce, timestampMs, apkPackageName, apkCertificateDigestSha256, apkDigestSha256, ctsProfileMatch, basicIntegrity, advice, null);
    }

    public @Nullable String getNonce() {
        return nonce;
    }

    public @Nullable Long getTimestampMs() {
        return timestampMs;
    }

    public @Nullable String getApkPackageName() {
        return apkPackageName;
    }

    public @Nullable String[] getApkCertificateDigestSha256() {
        return ArrayUtil.clone(apkCertificateDigestSha256);
    }

    public @Nullable String getApkDigestSha256() {
        return apkDigestSha256;
    }

    public @Nullable Boolean getCtsProfileMatch() {
        return ctsProfileMatch;
    }

    public @Nullable Boolean getBasicIntegrity() {
        return basicIntegrity;
    }

    public @Nullable String getAdvice() {
        return advice;
    }

    public @Nullable String getError() {
        return error;
    }

    @Override
    public String toString() {
        return "Response(" +
                "nonce=" + nonce +
                ", timestampMs=" + timestampMs +
                ", apkPackageName=" + apkPackageName +
                ", apkCertificateDigestSha256=" + Arrays.toString(apkCertificateDigestSha256) +
                ", apkDigestSha256=" + apkDigestSha256 +
                ", ctsProfileMatch=" + ctsProfileMatch +
                ", basicIntegrity=" + basicIntegrity +
                ", advice=" + advice +
                ", error=" + error +
                ')';
    }
}
