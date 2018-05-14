package net.sharplab.springframework.security.webauthn.sample.domain.vo;


import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.webauthn4j.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.attestation.statement.COSEKeyType;
import lombok.Data;
import lombok.EqualsAndHashCode;

import java.io.Serializable;

@JsonTypeInfo(use = JsonTypeInfo.Id.NAME)
@JsonSubTypes({
        @JsonSubTypes.Type(name = "RSACredentialPublicKey", value = RSCredentialPublicKeyVO.class),
        @JsonSubTypes.Type(name = "ECCredentialPublicKey", value = ECCredentialPublicKeyVO.class)
})
@Data
@EqualsAndHashCode
public abstract class AbstractCredentialPublicKeyVO implements CredentialPublicKeyVO, Serializable {

    private COSEKeyType keyType;
    private byte[] keyId;
    private int[] keyOpts;
    private byte[] baseIV;

    private COSEAlgorithmIdentifier algorithm;


}
