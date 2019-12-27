/*
 * Copyright 2018 the original author or authors.
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

package com.webauthn4j.metadata;

import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.data.attestation.statement.CertificateBaseAttestationStatement;
import com.webauthn4j.metadata.data.MetadataItem;
import com.webauthn4j.metadata.data.statement.AttestationType;
import com.webauthn4j.metadata.exception.BadStatusException;
import com.webauthn4j.validator.CustomRegistrationValidator;
import com.webauthn4j.validator.RegistrationObject;
import com.webauthn4j.validator.exception.BadAttestationStatementException;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class FidoMdsMetadataValidator implements CustomRegistrationValidator {


    private MetadataItemsResolver metadataItemsResolver;

    public FidoMdsMetadataValidator(MetadataItemsResolver metadataItemsResolver) {
        this.metadataItemsResolver = metadataItemsResolver;
    }

    public FidoMdsMetadataValidator(ObjectConverter objectConverter, String fidoMetadataServiceEndpoint) {
        FidoMdsMetadataItemsProvider metadataItemsProvider = new FidoMdsMetadataItemsProvider(objectConverter);
        metadataItemsProvider.setFidoMetadataServiceEndpoint(fidoMetadataServiceEndpoint);
        this.metadataItemsResolver = new MetadataItemsResolverImpl(metadataItemsProvider);
    }

    /**
     * @deprecated
     */
    @Deprecated
    public FidoMdsMetadataValidator(JsonConverter jsonConverter, String fidoMetadataServiceEndpoint) {
        FidoMdsMetadataItemsProvider metadataItemsProvider = new FidoMdsMetadataItemsProvider(jsonConverter);
        metadataItemsProvider.setFidoMetadataServiceEndpoint(fidoMetadataServiceEndpoint);
        this.metadataItemsResolver = new MetadataItemsResolverImpl(metadataItemsProvider);
    }

    public FidoMdsMetadataValidator(String fidoMetadataServiceEndpoint) {
        this(new ObjectConverter(), fidoMetadataServiceEndpoint);
    }

    @Override
    public void validate(RegistrationObject registrationObject) {
        AAGUID aaguid = registrationObject.getAttestationObject().getAuthenticatorData().getAttestedCredentialData().getAaguid();
        AttestationStatement attestationStatement = registrationObject.getAttestationObject().getAttestationStatement();

        Set<MetadataItem> metadataItems = metadataItemsResolver.resolve(aaguid);

        List<AttestationType> attestationTypes = metadataItems.stream()
                .flatMap(item -> item.getMetadataStatement().getAttestationTypes().stream()).collect(Collectors.toList());

        boolean isSurrogate = !attestationTypes.isEmpty() &&
                attestationTypes.stream().allMatch(type -> type.equals(AttestationType.BASIC_SURROGATE));

        if (isSurrogate && attestationStatement instanceof CertificateBaseAttestationStatement) {
            CertificateBaseAttestationStatement certificateBaseAttestationStatement = (CertificateBaseAttestationStatement) attestationStatement;
            if (certificateBaseAttestationStatement.getX5c() != null) {
                throw new BadAttestationStatementException("Although AAGUID is registered for surrogate attestation in metadata, x5c contains certificates.");
            }
        }

        for (MetadataItem metadataItem : metadataItems) {
            doAdditionalValidationForFidoMdsMetadataItem(metadataItem);
        }
    }

    private void doAdditionalValidationForFidoMdsMetadataItem(MetadataItem metadataItem) {
        metadataItem.getStatusReports().forEach(report -> {
            switch (report.getStatus()) {
                case FIDO_CERTIFIED:
                case FIDO_CERTIFIED_L1:
                case FIDO_CERTIFIED_L1_PLUS:
                case FIDO_CERTIFIED_L2:
                case FIDO_CERTIFIED_L2_PLUS:
                case FIDO_CERTIFIED_L3:
                case FIDO_CERTIFIED_L3_PLUS:
                case UPDATE_AVAILABLE:
                case NOT_FIDO_CERTIFIED:
                case SELF_ASSERTION_SUBMITTED:
                    return;
                case ATTESTATION_KEY_COMPROMISE:
                case USER_VERIFICATION_BYPASS:
                case USER_KEY_REMOTE_COMPROMISE:
                case USER_KEY_PHYSICAL_COMPROMISE:
                case REVOKED:
                default:
                    throw new BadStatusException(String.format("FIDO Metadata Service reported `%s` for this authenticator.", report.getStatus()));
            }
        });
    }

}
