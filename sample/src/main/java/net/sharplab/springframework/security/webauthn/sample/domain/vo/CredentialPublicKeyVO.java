package net.sharplab.springframework.security.webauthn.sample.domain.vo;


import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import lombok.Data;

import java.io.Serializable;

@JsonTypeInfo(use = JsonTypeInfo.Id.NAME)
@JsonSubTypes({
        @JsonSubTypes.Type(name = "RSCredentialPublicKey", value = RSCredentialPublicKeyVO.class),
        @JsonSubTypes.Type(name = "ESCredentialPublicKey", value = ESCredentialPublicKeyVO.class)
})
@Data
public class CredentialPublicKeyVO implements Serializable {

    private int keyType;
    private byte[] keyId;
    private int algorithm;
    private int[] keyOpts;
    private byte[] baseIV;

}
