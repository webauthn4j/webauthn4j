package net.sharplab.springframework.security.webauthn.sample.domain.vo;

import com.webauthn4j.attestation.authenticator.RSSignatureAlgorithm;
import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@EqualsAndHashCode(callSuper = true)
public class RSCredentialPublicKeyVO extends AbstractCredentialPublicKeyVO {

    private RSSignatureAlgorithm algorithm;
    private byte[] n;
    private byte[] e;
}
