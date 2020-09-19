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

package com.webauthn4j.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

import java.util.Objects;

import static com.webauthn4j.data.MessageDigestAlgorithm.*;

public class SignatureAlgorithm {

    public static final SignatureAlgorithm ES256 = new SignatureAlgorithm("SHA256withECDSA", SHA256);
    public static final SignatureAlgorithm ES384 = new SignatureAlgorithm("SHA384withECDSA", SHA384);
    public static final SignatureAlgorithm ES512 = new SignatureAlgorithm("SHA512withECDSA", SHA512);
    public static final SignatureAlgorithm RS1   = new SignatureAlgorithm("SHA1withRSA",     SHA1);
    public static final SignatureAlgorithm RS256 = new SignatureAlgorithm("SHA256withRSA", SHA256);
    public static final SignatureAlgorithm RS384 = new SignatureAlgorithm("SHA384withRSA", SHA384);
    public static final SignatureAlgorithm RS512 = new SignatureAlgorithm("SHA512withRSA", SHA512);

    private final String jcaName;
    private final MessageDigestAlgorithm messageDigestAlgorithm;

    private SignatureAlgorithm(String jcaName, MessageDigestAlgorithm messageDigestAlgorithm) {
        this.jcaName = jcaName;
        this.messageDigestAlgorithm = messageDigestAlgorithm;
    }

    @JsonCreator
    public static SignatureAlgorithm create(String jcaName){
        switch (jcaName){
            case "SHA256withECDSA":
                return ES256;
            case "SHA384withECDSA":
                return ES384;
            case "SHA512withECDSA":
                return ES512;
            case "SHA1withRSA":
                return RS1;
            case "SHA256withRSA":
                return RS256;
            case "SHA384withRSA":
                return RS384;
            case "SHA512withRSA":
                return RS512;
            default:
                throw new IllegalArgumentException(String.format("jcaName %s is not supported.", jcaName));
        }
    }

    public static SignatureAlgorithm create(String jcaName, String messageDigestJcaName){
        return new SignatureAlgorithm(jcaName, MessageDigestAlgorithm.create(messageDigestJcaName));
    }

    @JsonValue
    public String getJcaName() {
        return jcaName;
    }

    public MessageDigestAlgorithm getMessageDigestAlgorithm() {
        return messageDigestAlgorithm;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SignatureAlgorithm that = (SignatureAlgorithm) o;
        return Objects.equals(jcaName, that.jcaName) &&
                Objects.equals(messageDigestAlgorithm, that.messageDigestAlgorithm);
    }

    @Override
    public int hashCode() {
        return Objects.hash(jcaName, messageDigestAlgorithm);
    }
}
