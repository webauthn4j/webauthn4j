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

package com.webauthn4j.extras.fido.metadata.statement;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Created by ynojima on 2017/09/08.
 */
public class MetadataStatement {
    private String legalHeader;
    private String aaid;
    private String aaguid;
    private List<String> attestationCertificateKeyIdentifiers;
    private AlternativeDescriptions alternativeDescriptions;
    private Integer authenticatorVersion;
    private String protocolFamily;
    private List<Version> upv;
    private String assertionScheme;
    private Integer authenticationAlgorithm;
    private List<Integer> authenticationAlgorithms;
    private Integer publicKeyAlgAndEncoding;
    private List<Integer> publicKeyAlgAndEncodings;
    private List<Integer> attestationTypes;
    private List<VerificationMethodANDCombinations> userVerificationDetails;
    private Integer keyProtection;
    private Boolean isKeyRestricted;
    private Boolean isFreshUserVerificationRequired;
    private Integer matcherProtection;
    private Integer cryptoStrength;
    private String operationEnv;
    private BigInteger attachmentHint;
    private Boolean isSecondFactorOnly;
    private Integer tcDisplay;
    private String tcDisplayContentType;
    private List<DisplayPNGCharacteristicsDescriptor> tcDisplayPNGCharacteristics;
    private List<X509Certificate> attestationRootCertificates;
    private List<EcdaaTrustAnchor> ecdaaTrustAnchors;
    private String icon;
    private List<ExtensionDescriptor> supportedExtensions;

    public String getLegalHeader() {
        return legalHeader;
    }

    public String getAaid() {
        return aaid;
    }

    public String getAaguid() {
        return aaguid;
    }

    public List<String> getAttestationCertificateKeyIdentifiers() {
        return attestationCertificateKeyIdentifiers;
    }

    public AlternativeDescriptions getAlternativeDescriptions() {
        return alternativeDescriptions;
    }

    public Integer getAuthenticatorVersion() {
        return authenticatorVersion;
    }

    public String getProtocolFamily() {
        return protocolFamily;
    }

    public List<Version> getUpv() {
        return upv;
    }

    public String getAssertionScheme() {
        return assertionScheme;
    }

    public Integer getAuthenticationAlgorithm() {
        return authenticationAlgorithm;
    }

    public List<Integer> getAuthenticationAlgorithms() {
        return authenticationAlgorithms;
    }

    public Integer getPublicKeyAlgAndEncoding() {
        return publicKeyAlgAndEncoding;
    }

    public List<Integer> getPublicKeyAlgAndEncodings() {
        return publicKeyAlgAndEncodings;
    }

    public List<Integer> getAttestationTypes() {
        return attestationTypes;
    }

    public List<VerificationMethodANDCombinations> getUserVerificationDetails() {
        return userVerificationDetails;
    }

    public Integer getKeyProtection() {
        return keyProtection;
    }

    public Boolean getKeyRestricted() {
        return isKeyRestricted;
    }

    public Boolean getFreshUserVerificationRequired() {
        return isFreshUserVerificationRequired;
    }

    public Integer getMatcherProtection() {
        return matcherProtection;
    }

    public Integer getCryptoStrength() {
        return cryptoStrength;
    }

    public String getOperationEnv() {
        return operationEnv;
    }

    public BigInteger getAttachmentHint() {
        return attachmentHint;
    }

    public Boolean getSecondFactorOnly() {
        return isSecondFactorOnly;
    }

    public Integer getTcDisplay() {
        return tcDisplay;
    }

    public String getTcDisplayContentType() {
        return tcDisplayContentType;
    }

    public List<DisplayPNGCharacteristicsDescriptor> getTcDisplayPNGCharacteristics() {
        return tcDisplayPNGCharacteristics;
    }

    public List<X509Certificate> getAttestationRootCertificates() {
        return attestationRootCertificates;
    }

    public List<EcdaaTrustAnchor> getEcdaaTrustAnchors() {
        return ecdaaTrustAnchors;
    }

    public String getIcon() {
        return icon;
    }

    public List<ExtensionDescriptor> getSupportedExtensions() {
        return supportedExtensions;
    }
}
