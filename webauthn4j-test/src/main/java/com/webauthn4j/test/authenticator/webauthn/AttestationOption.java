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

package com.webauthn4j.test.authenticator.webauthn;

@SuppressWarnings("WeakerAccess")
public abstract class AttestationOption {
    protected String subjectDN = "";
    protected boolean caFlagInBasicConstraints = false;
    protected int x509CertificateVersion = 3;

    public String getSubjectDN() {
        return subjectDN;
    }

    public void setSubjectDN(String subjectDN) {
        this.subjectDN = subjectDN;
    }

    public boolean isCAFlagInBasicConstraints() {
        return caFlagInBasicConstraints;
    }

    public void setCAFlagInBasicConstraints(boolean caFlagInBasicConstraints) {
        this.caFlagInBasicConstraints = caFlagInBasicConstraints;
    }

    public int getX509CertificateVersion() {
        return x509CertificateVersion;
    }

    public void setX509CertificateVersion(int x509CertificateVersion) {
        this.x509CertificateVersion = x509CertificateVersion;
    }
}
