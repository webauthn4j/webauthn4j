package net.sharplab.springframework.security.webauthn.sample.domain.vo;


import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.webauthn4j.attestation.authenticator.AbstractSignatureAlgorithm;
import lombok.Data;
import lombok.EqualsAndHashCode;

import java.io.Serializable;

@JsonTypeInfo(use = JsonTypeInfo.Id.NAME)
@JsonSubTypes({
        @JsonSubTypes.Type(name = "RSCredentialPublicKey", value = RSCredentialPublicKeyVO.class),
        @JsonSubTypes.Type(name = "ESCredentialPublicKey", value = ESCredentialPublicKeyVO.class)
})
@Data
@EqualsAndHashCode
public abstract class AbstractCredentialPublicKeyVO implements CredentialPublicKeyVO, Serializable {

    private int keyType;
    private byte[] keyId;
    private int[] keyOpts;
    private byte[] baseIV;

}
