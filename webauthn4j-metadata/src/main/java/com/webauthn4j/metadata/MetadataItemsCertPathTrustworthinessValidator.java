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

package com.webauthn4j.metadata;

import com.webauthn4j.metadata.data.FidoMdsMetadataItem;
import com.webauthn4j.metadata.data.MetadataItem;
import com.webauthn4j.metadata.data.statement.AttestationType;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.statement.CertificateBaseAttestationStatement;
import com.webauthn4j.util.WIP;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.CertPathTrustworthinessValidatorBase;
import com.webauthn4j.validator.exception.BadAttestationStatementException;
import com.webauthn4j.validator.exception.CertificateException;

import java.security.cert.TrustAnchor;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * MetadataItemsCertPathTrustworthinessValidator
 */
@WIP
public class MetadataItemsCertPathTrustworthinessValidator<T extends MetadataItem> extends CertPathTrustworthinessValidatorBase {

    private MetadataItemsResolver<T> metadataItemsResolver;

    public MetadataItemsCertPathTrustworthinessValidator(MetadataItemsResolver<T> metadataItemsResolver) {
        this.metadataItemsResolver = metadataItemsResolver;
    }

    @Override
    public void validate(AAGUID aaguid, CertificateBaseAttestationStatement attestationStatement) {
        Set<T> metadataItems = metadataItemsResolver.resolve(aaguid);

        //TODO: this logic should be placed in another class. It is domain violation.
        List<AttestationType> attestationTypes = metadataItems.stream()
                .flatMap(item -> item.getMetadataStatement().getAttestationTypes().stream()).collect(Collectors.toList());
        boolean isSurrogate = !attestationTypes.isEmpty() &&
                attestationTypes.stream().allMatch(type -> type.equals(AttestationType.BASIC_SURROGATE));
        if (isSurrogate && attestationStatement.getX5c() != null) {
            throw new BadAttestationStatementException("Although AAGUID is registered for surrogate attestation in metadata, x5c contains certificates.");
        }

        for (T metadataItem : metadataItems) {
            if (metadataItem instanceof FidoMdsMetadataItem) {
                FidoMdsMetadataItem fidoMdsMetadataItem = (FidoMdsMetadataItem) metadataItem;
                doAdditionalValidationForFidoMdsMetadataItem(fidoMdsMetadataItem);
            }
        }
        super.validate(aaguid, attestationStatement);
    }

    private void doAdditionalValidationForFidoMdsMetadataItem(FidoMdsMetadataItem fidoMdsMetadataItem) {
        fidoMdsMetadataItem.getStatusReports().forEach(report -> {
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
                    throw new CertificateException(String.format("error response from fidoMdsMetadataItem service: %s", report.getStatus()));
            }
        });
    }

    @Override
    protected Set<TrustAnchor> resolveTrustAnchors(AAGUID aaguid) {
        return metadataItemsResolver.resolve(aaguid).stream()
                .flatMap(metadataItem -> metadataItem.getMetadataStatement().getAttestationRootCertificates().stream())
                .map(certificate -> new TrustAnchor(certificate, null))
                .collect(Collectors.toSet());
    }


}
