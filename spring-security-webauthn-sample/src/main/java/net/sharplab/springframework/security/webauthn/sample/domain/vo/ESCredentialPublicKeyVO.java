package net.sharplab.springframework.security.webauthn.sample.domain.vo;

import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@EqualsAndHashCode(callSuper = true)
public class ESCredentialPublicKeyVO extends CredentialPublicKeyVO {

    private int curve;
    private byte[] x;
    private byte[] y;
    private byte[] d;

}
