package net.sharplab.springframework.security.webauthn.sample.domain.vo;

import lombok.Data;
import net.sharplab.springframework.security.webauthn.sample.infrastructure.util.jpa.converter.CredentialPublicKeyVOConverter;

import javax.persistence.Column;
import javax.persistence.Convert;
import javax.persistence.Embeddable;
import java.io.Serializable;

/**
 * AttestedCredentialDataVO
 */
@Data
@Embeddable
public class AttestedCredentialDataVO implements Serializable {

    private byte[] aaGuid;

    private byte[] credentialId;

    @Column(columnDefinition = "text")
    @Convert(converter = CredentialPublicKeyVOConverter.class)
    private CredentialPublicKeyVO credentialPublicKey;

}
