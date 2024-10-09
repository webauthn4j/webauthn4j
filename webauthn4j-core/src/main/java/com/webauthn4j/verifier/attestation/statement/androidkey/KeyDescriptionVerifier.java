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

// Some code fragment in this file is based on android key attestation sample provided by the Android Open Source Project.
// https://github.com/googlesamples/android-key-attestation

package com.webauthn4j.verifier.attestation.statement.androidkey;

import com.webauthn4j.converter.internal.asn1.ASN1;
import com.webauthn4j.converter.internal.asn1.ASN1Primitive;
import com.webauthn4j.converter.internal.asn1.ASN1Sequence;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.verifier.exception.BadAttestationStatementException;
import com.webauthn4j.verifier.exception.KeyDescriptionValidationException;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Objects;

import static com.webauthn4j.converter.internal.asn1.ASN1Tag.INTEGER;

public class KeyDescriptionVerifier {

    public static final String ATTESTATION_EXTENSION_OID = "1.3.6.1.4.1.11129.2.1.17";
    public static final int ATTESTATION_CHALLENGE_INDEX = 4;
    public static final int SW_ENFORCED_INDEX = 6;
    public static final int TEE_ENFORCED_INDEX = 7;
    public static final int KM_TAG_PURPOSE = 1;
    public static final int KM_TAG_ALL_APPLICATIONS = 600;
    public static final int KM_TAG_CREATION_DATE_TIME = 701;
    public static final int KM_TAG_ORIGIN = 702;
    public static final int KM_ORIGIN_GENERATED = 0;
    public static final int KM_PURPOSE_SIGN = 2;

    // ~ Instance fields
    // ================================================================================================

    private final Logger logger = LoggerFactory.getLogger(KeyDescriptionVerifier.class);

    public void verify(@NotNull X509Certificate x509Certificate, @NotNull byte[] clientDataHash, boolean teeEnforcedOnly) {
        AssertUtil.notNull(x509Certificate, "x509Certificate must not be null");
        AssertUtil.notNull(clientDataHash, "clientDataHash must not be null");

        try {
            ASN1Sequence keyDescription = extractKeyDescription(x509Certificate);
            doVerify(keyDescription, clientDataHash, teeEnforcedOnly);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @NotNull ASN1Sequence extractKeyDescription(@NotNull X509Certificate x509Certificate) throws IOException {

        byte[] attestationExtensionBytes = x509Certificate.getExtensionValue(ATTESTATION_EXTENSION_OID);

        if (attestationExtensionBytes == null) {
            throw new KeyDescriptionValidationException("KeyDescription must not be null");
        }
        return (ASN1Sequence) ASN1Primitive.parse(attestationExtensionBytes).getValueAsASN1();
    }

    void doVerify(@NotNull ASN1Sequence keyDescription, @NotNull byte[] clientDataHash, boolean teeEnforcedOnly) throws IOException {
        /// Verify that the attestationChallenge field in the attestation certificate extension data is identical to clientDataHash.
        byte[] attestationChallenge = ((ASN1Primitive) keyDescription.get(ATTESTATION_CHALLENGE_INDEX)).getValue();
        // As attestationChallenge is known data to client side(potential attacker) because it is calculated from parts of a message,
        // there is no need to prevent timing attack and it is OK to use `Arrays.equals` instead of `MessageDigest.isEqual` here.
        if (!Arrays.equals(attestationChallenge, clientDataHash)) {
            throw new KeyDescriptionValidationException("Attestation challenge doesn't match.");
        }

        /// Verify the following using the appropriate authorization list from the attestation certificate extension data:

        /// The AuthorizationList.allApplications field is not present on either authorization list (softwareEnforced nor teeEnforced), since PublicKeyCredential MUST be scoped to the RP ID.
        ASN1Sequence softwareEnforced = (ASN1Sequence) keyDescription.get(SW_ENFORCED_INDEX);
        ASN1Sequence teeEnforced = (ASN1Sequence) keyDescription.get(TEE_ENFORCED_INDEX);

        if (findAuthorizationListEntry(softwareEnforced, KM_TAG_ALL_APPLICATIONS) != null ||
                findAuthorizationListEntry(teeEnforced, KM_TAG_ALL_APPLICATIONS) != null) {
            throw new KeyDescriptionValidationException("Key is not scoped properly.");
        }

        verifyAuthorizationList(teeEnforcedOnly, softwareEnforced, teeEnforced);
    }

    private void verifyAuthorizationList(boolean teeEnforcedOnly, @NotNull ASN1Sequence softwareEnforced, @NotNull ASN1Sequence teeEnforced) throws IOException {
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

    @SuppressWarnings("BooleanMethodIsAlwaysInverted")
    private boolean isKeyGeneratedInKeymaster(@Nullable ASN1 origin) {
        try {
            return Objects.equals(getIntegerFromAsn1(origin), BigInteger.valueOf(KM_ORIGIN_GENERATED));
        } catch (RuntimeException | IOException e) {
            logger.debug("Failed to retrieve origin.", e);
            return false;
        }
    }

    @SuppressWarnings("BooleanMethodIsAlwaysInverted")
    private boolean containsValidPurpose(@Nullable ASN1 purposes) throws IOException {
        try {
            if (purposes == null) {
                return false;
            }
            ASN1Sequence set = (ASN1Sequence)purposes;
            for (Object valueItem: set) {
                ASN1Primitive purpose = (ASN1Primitive) valueItem;
                if (Objects.equals(getIntegerFromAsn1(purpose), BigInteger.valueOf(KM_PURPOSE_SIGN))) {
                    return true;
                }
            }
            return false;
        } catch (RuntimeException e) {
            logger.debug("Failed to retrieve purpose.", e);
            return false;
        }
    }


    private @Nullable BigInteger getIntegerFromAsn1(ASN1 asn1Value) throws IOException {
        if (asn1Value == null) {
            return null;
        }
        if (!(asn1Value.getClass() == ASN1Primitive.class && asn1Value.getTag().getNumber() == INTEGER)) {
            throw new BadAttestationStatementException(String.format("ASN1Integer is expected. Found %s instead.", asn1Value.getClass().getName()));
        }
        return ((ASN1Primitive)asn1Value).getValueAsBigInteger();
    }

    private @Nullable ASN1 findAuthorizationListEntry(@NotNull ASN1Sequence authorizationList, int tag) {
        for (Object listItem : authorizationList) {
            ASN1Sequence entry = (ASN1Sequence)listItem;
            if (entry.getTag().getNumber() == tag) {
                return entry.get(0);
            }
        }
        return null;
    }


}
