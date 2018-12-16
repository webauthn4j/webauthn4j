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

package com.webauthn4j.validator.attestation.androidkey;

import com.webauthn4j.validator.exception.KeyDescriptionValidationException;
import com.webauthn4j.validator.exception.BadAttestationStatementException;
import org.bouncycastle.asn1.*;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public class KeyDescriptionValidator {

    private Logger logger = LoggerFactory.getLogger(KeyDescriptionValidator.class);

    private static final String ATTESTATION_EXTENSION_OID = "1.3.6.1.4.1.11129.2.1.17";

    private static final int ATTESTATION_CHALLENGE_INDEX = 4;
    private static final int SW_ENFORCED_INDEX = 6;
    private static final int TEE_ENFORCED_INDEX = 7;

    private static final int KM_TAG_PURPOSE = 1;
    private static final int KM_TAG_ALL_APPLICATIONS  = 600;
    private static final int KM_TAG_ORIGIN = 702;

    private static final int KM_ORIGIN_GENERATED = 0;

    private static final int KM_PURPOSE_SIGN = 2;

    public void validate(X509Certificate x509Certificate, byte[] clientDataHash, boolean teeEnforcedOnly){
        ASN1Sequence attestationExtension = getAttestationExtension(x509Certificate);

        /// Verify that the attestationChallenge field in the attestation certificate extension data is identical to clientDataHash.
        byte[] attestationChallenge = ((ASN1OctetString)attestationExtension.getObjectAt(ATTESTATION_CHALLENGE_INDEX)).getOctets();
        if(!Arrays.equals(attestationChallenge, clientDataHash)){
            throw new KeyDescriptionValidationException("Bad attestation challenge exception");
        }

        /// Verify the following using the appropriate authorization list from the attestation certificate extension data:
        /// The AuthorizationList.allApplications field is not present on either authorization list (softwareEnforced nor teeEnforced), since PublicKeyCredential MUST be scoped to the RP ID.
        ASN1Encodable[] softwareEnforced = ((ASN1Sequence)attestationExtension.getObjectAt(SW_ENFORCED_INDEX)).toArray();
        ASN1Encodable[] teeEnforced = ((ASN1Sequence)attestationExtension.getObjectAt(TEE_ENFORCED_INDEX)).toArray();

        if (findAuthorizationListEntry(softwareEnforced, KM_TAG_ALL_APPLICATIONS) != null ||
                findAuthorizationListEntry(teeEnforced, KM_TAG_ALL_APPLICATIONS) != null) {
            throw new KeyDescriptionValidationException("Key is not scoped properly.");
        }

        /// For the following, use only the teeEnforced authorization list if the RP wants to accept only keys
        /// from a trusted execution environment, otherwise use the union of teeEnforced and softwareEnforced.
        /// The value in the AuthorizationList.origin field is equal to KM_ORIGIN_GENERATED.
        /// The value in the AuthorizationList.purpose field is equal to KM_PURPOSE_SIGN.
        if(teeEnforcedOnly){
            if(!isKeyGeneratedInKeymaster(findAuthorizationListEntry(teeEnforced, KM_TAG_ORIGIN))){
                throw new KeyDescriptionValidationException("Key is not generated in keymaster.");
            }
            if(!containsValidPurpose(findAuthorizationListEntry(teeEnforced, KM_TAG_PURPOSE))){
                throw new KeyDescriptionValidationException("Key purpose is invalid.");
            }
        }
        else {
            if(!isKeyGeneratedInKeymaster(findAuthorizationListEntry(teeEnforced, KM_TAG_ORIGIN)) &&
               !isKeyGeneratedInKeymaster(findAuthorizationListEntry(softwareEnforced, KM_TAG_ORIGIN))){

                throw new KeyDescriptionValidationException("Key is not generated in keymaster.");
            }
            if(!containsValidPurpose(findAuthorizationListEntry(teeEnforced, KM_TAG_PURPOSE)) &&
               !containsValidPurpose(findAuthorizationListEntry(softwareEnforced, KM_TAG_PURPOSE))){
                throw new KeyDescriptionValidationException("Key purpose is invalid.");
            }
        }
    }

    private boolean isKeyGeneratedInKeymaster(ASN1Primitive origin){
        try{
            return getIntegerFromAsn1(origin).equals(BigInteger.valueOf(KM_ORIGIN_GENERATED));
        }
        catch (RuntimeException e){
            logger.debug("Failed to retrieve origin.", e);
            return false;
        }
    }

    private boolean containsValidPurpose(ASN1Primitive purposes){
        try{
            ASN1Set set = (ASN1Set) purposes;
            for (ASN1Encodable purpose : set.toArray()){
                try{
                    if(getIntegerFromAsn1(purpose).equals(BigInteger.valueOf(KM_PURPOSE_SIGN))){
                        return true;
                    }
                }
                catch (RuntimeException e){
                    logger.debug("Failed to retrieve purpose.", e);
                    return false;
                }
            }
            return false;
        }
        catch (RuntimeException e){
            logger.debug("Failed to retrieve purpose.", e);
            return false;
        }
    }


    BigInteger getIntegerFromAsn1(ASN1Encodable asn1Value) {
        if (asn1Value instanceof ASN1Integer) {
            return ((ASN1Integer)asn1Value).getValue();
        }
        else {
            throw new BadAttestationStatementException("ASN1Integer is expected; found "
                    + asn1Value.getClass().getName()
                    + " instead.");
        }
    }

    ASN1Primitive findAuthorizationListEntry(
            ASN1Encodable[] authorizationList, int tag) {
        for (ASN1Encodable entry : authorizationList) {
            ASN1TaggedObject taggedEntry = (ASN1TaggedObject) entry;
            if (taggedEntry.getTagNo() == tag) {
                return taggedEntry.getObject();
            }
        }
        return null;
    }

    ASN1Sequence getAttestationExtension(X509Certificate x509Certificate){
        byte[] attestationExtensionBytes = x509Certificate.getExtensionValue(ATTESTATION_EXTENSION_OID);
        if (attestationExtensionBytes == null || attestationExtensionBytes.length == 0) {
            throw new KeyDescriptionValidationException("The keystore attestation extension is missing.");
        }
        try {
            return (ASN1Sequence)JcaX509ExtensionUtils.parseExtensionValue(attestationExtensionBytes);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }


}
