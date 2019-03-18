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

// Some code fragment in this file is based on android key attestation sample provided by the Android Open Source Project.
// https://github.com/googlesamples/android-key-attestation

package com.webauthn4j.validator.attestation.statement.androidkey;

import com.webauthn4j.validator.exception.BadAttestationStatementException;
import com.webauthn4j.validator.exception.KeyDescriptionValidationException;
import org.apache.kerby.asn1.parse.Asn1Container;
import org.apache.kerby.asn1.parse.Asn1ParseResult;
import org.apache.kerby.asn1.parse.Asn1Parser;
import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.asn1.type.Asn1OctetString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.cert.X509Certificate;
import java.util.Arrays;

class KeyDescriptionValidator {

    private static final String ATTESTATION_EXTENSION_OID = "1.3.6.1.4.1.11129.2.1.17";
    private static final int ATTESTATION_CHALLENGE_INDEX = 4;
    private static final int SW_ENFORCED_INDEX = 6;
    private static final int TEE_ENFORCED_INDEX = 7;
    private static final int KM_TAG_PURPOSE = 1;
    private static final int KM_TAG_ALL_APPLICATIONS = 600;
    private static final int KM_TAG_ORIGIN = 702;
    private static final int KM_ORIGIN_GENERATED = 0;
    private static final int KM_PURPOSE_SIGN = 2;

    // ~ Instance fields
    // ================================================================================================

    private Logger logger = LoggerFactory.getLogger(KeyDescriptionValidator.class);

    public void validate(X509Certificate x509Certificate, byte[] clientDataHash, boolean teeEnforcedOnly) {
        try {
            Asn1Container keyDescription = extractKeyDescription(x509Certificate);
            doValidate(keyDescription, clientDataHash, teeEnforcedOnly);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    Asn1Container extractKeyDescription(X509Certificate x509Certificate) throws IOException {

        byte[] attestationExtensionBytes = x509Certificate.getExtensionValue(ATTESTATION_EXTENSION_OID);
        Asn1OctetString container = new Asn1OctetString();
        container.decode(attestationExtensionBytes);
        return  (Asn1Container)Asn1Parser.parse(ByteBuffer.wrap(container.getValue()));
    }

    void doValidate(Asn1Container keyDescription, byte[] clientDataHash, boolean teeEnforcedOnly) throws IOException {
        /// Verify that the attestationChallenge field in the attestation certificate extension data is identical to clientDataHash.
        byte[] attestationChallenge = keyDescription.getChildren().get(ATTESTATION_CHALLENGE_INDEX).readBodyBytes();
        if (!Arrays.equals(attestationChallenge, clientDataHash)) {
            throw new KeyDescriptionValidationException("Attestation challenge doesn't match.");
        }

        /// Verify the following using the appropriate authorization list from the attestation certificate extension data:

        /// The AuthorizationList.allApplications field is not present on either authorization list (softwareEnforced nor teeEnforced), since PublicKeyCredential MUST be scoped to the RP ID.
        Asn1Container softwareEnforced = (Asn1Container) keyDescription.getChildren().get(SW_ENFORCED_INDEX);
        Asn1Container teeEnforced = (Asn1Container) keyDescription.getChildren().get(TEE_ENFORCED_INDEX);

        if (findAuthorizationListEntry(softwareEnforced, KM_TAG_ALL_APPLICATIONS) != null ||
                findAuthorizationListEntry(teeEnforced, KM_TAG_ALL_APPLICATIONS) != null) {
            throw new KeyDescriptionValidationException("Key is not scoped properly.");
        }

        validateAuthorizationList(teeEnforcedOnly, softwareEnforced, teeEnforced);
    }

    private void validateAuthorizationList(boolean teeEnforcedOnly, Asn1Container softwareEnforced, Asn1Container teeEnforced) throws IOException {
        /// For the following,
        /// use only the teeEnforced authorization list if the RP wants to accept only keys
        /// from a trusted execution environment,
        if (teeEnforcedOnly) {
            /// The value in the AuthorizationList.origin field is equal to KM_ORIGIN_GENERATED.
            /// The value in the AuthorizationList.purpose field is equal to KM_PURPOSE_SIGN.
            if (!isKeyGeneratedInKeymaster(findAuthorizationListEntry(teeEnforced, KM_TAG_ORIGIN))) {
                throw new KeyDescriptionValidationException("Key is not generated in keymaster.");
            }
            if (!containsValidPurpose(findAuthorizationListEntry(teeEnforced, KM_TAG_PURPOSE))) {
                throw new KeyDescriptionValidationException("Key purpose is invalid.");
            }
        }
        /// otherwise use the union of teeEnforced and softwareEnforced.
        else {
            /// The value in the AuthorizationList.origin field is equal to KM_ORIGIN_GENERATED.
            /// The value in the AuthorizationList.purpose field is equal to KM_PURPOSE_SIGN.
            if (!isKeyGeneratedInKeymaster(findAuthorizationListEntry(teeEnforced, KM_TAG_ORIGIN)) &&
                    !isKeyGeneratedInKeymaster(findAuthorizationListEntry(softwareEnforced, KM_TAG_ORIGIN))) {

                throw new KeyDescriptionValidationException("Key is not generated in keymaster.");
            }
            if (!containsValidPurpose(findAuthorizationListEntry(teeEnforced, KM_TAG_PURPOSE)) &&
                    !containsValidPurpose(findAuthorizationListEntry(softwareEnforced, KM_TAG_PURPOSE))) {
                throw new KeyDescriptionValidationException("Key purpose is invalid.");
            }
        }
    }

    private boolean isKeyGeneratedInKeymaster(Asn1ParseResult origin) {
        try {
            return getIntegerFromAsn1(origin).equals(BigInteger.valueOf(KM_ORIGIN_GENERATED));
        } catch (RuntimeException | IOException e) {
            logger.debug("Failed to retrieve origin.", e);
            return false;
        }
    }

    private boolean containsValidPurpose(Asn1ParseResult purposes) throws IOException {
        try {
            if(purposes == null){
                return false;
            }
            Asn1Container set = (Asn1Container) purposes;
            for (Asn1ParseResult purpose : set.getChildren()) {
                if (getIntegerFromAsn1(purpose).equals(BigInteger.valueOf(KM_PURPOSE_SIGN))) {
                    return true;
                }
            }
            return false;
        } catch (RuntimeException e) {
            logger.debug("Failed to retrieve purpose.", e);
            return false;
        }
    }


    private BigInteger getIntegerFromAsn1(Asn1ParseResult asn1Value) throws IOException {
        if (!asn1Value.isPrimitive()) {
            throw new BadAttestationStatementException(String.format("ASN1Integer is expected. Found %s instead.", asn1Value.getClass().getName()));
        }
        Asn1Integer value = new Asn1Integer();
        value.decode(asn1Value);
        return value.getValue();
    }

    private Asn1ParseResult findAuthorizationListEntry(
            Asn1Container authorizationList, int tag) {
        for (Asn1ParseResult entry : authorizationList.getChildren()) {
            Asn1ParseResult taggedEntry = entry;
            if (taggedEntry.tagNo() == tag) {
                return ((Asn1Container)taggedEntry).getChildren().get(0);
            }
        }
        return null;
    }



}
