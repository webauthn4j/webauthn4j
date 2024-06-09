package com.webauthn4j.metadata.util.internal;

import com.webauthn4j.data.AuthenticatorAttestationType;
import com.webauthn4j.metadata.data.statement.MetadataStatement;

public class MetadataStatementUtil {

    private MetadataStatementUtil(){}

    public static boolean checkSurrogateMetadataStatementAttestationRootCertificate(MetadataStatement metadataStatement) {
        boolean isSurrogate = metadataStatement != null && metadataStatement.getAttestationTypes().stream().allMatch(type -> type.equals(AuthenticatorAttestationType.BASIC_SURROGATE));

        if (isSurrogate) {
            return metadataStatement.getAttestationRootCertificates().isEmpty();
        }
        return true;
    }
}
