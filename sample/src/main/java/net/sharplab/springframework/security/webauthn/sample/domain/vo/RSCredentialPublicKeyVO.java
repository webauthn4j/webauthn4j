package net.sharplab.springframework.security.webauthn.sample.domain.vo;

import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@EqualsAndHashCode(callSuper = true)
public class RSCredentialPublicKeyVO extends AbstractCredentialPublicKeyVO {

    private byte[] n;
    private byte[] e;
}
