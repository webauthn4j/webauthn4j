package net.sharplab.springframework.security.webauthn.sample.util.modelmapper;

import com.webauthn4j.attestation.authenticator.CredentialPublicKey;
import com.webauthn4j.attestation.authenticator.ECCredentialPublicKey;
import com.webauthn4j.attestation.authenticator.RSACredentialPublicKey;
import net.sharplab.springframework.security.webauthn.sample.domain.vo.CredentialPublicKeyVO;
import net.sharplab.springframework.security.webauthn.sample.domain.vo.ECCredentialPublicKeyVO;
import net.sharplab.springframework.security.webauthn.sample.domain.vo.RSCredentialPublicKeyVO;
import org.modelmapper.Converter;
import org.modelmapper.spi.MappingContext;


/**
 * Converter which converts from {@link CredentialPublicKeyVO} to {@link CredentialPublicKey}
 */
public class CredentialPublicKeyVOToCredentialPublicKeyConverter implements Converter<CredentialPublicKeyVO, CredentialPublicKey> {
    @Override
    public CredentialPublicKey convert(MappingContext<CredentialPublicKeyVO, CredentialPublicKey> context) {
        CredentialPublicKeyVO source = context.getSource();
        CredentialPublicKey destination = context.getDestination();
        if (source == null) {
            return null;
        }
        if (source.getClass() == RSCredentialPublicKeyVO.class) {
            if (destination == null) {
                destination = new RSACredentialPublicKey();
            }
            context.getMappingEngine().map(context.create((RSCredentialPublicKeyVO) source, (RSACredentialPublicKey)destination));
        } else if (source.getClass() == ECCredentialPublicKeyVO.class) {
            if (destination == null) {
                destination = new ECCredentialPublicKey();
            }
            context.getMappingEngine().map(context.create((ECCredentialPublicKeyVO) source, (ECCredentialPublicKey)destination));
        } else {
            throw new IllegalArgumentException();
        }
        return destination;
    }
}
