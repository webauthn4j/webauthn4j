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
 * Converter which converts from {@link CredentialPublicKey} to {@link CredentialPublicKeyVO}
 */
public class CredentialPublicKeyToCredentialPublicKeyVOConverter implements Converter<CredentialPublicKey, CredentialPublicKeyVO> {
    @Override
    public CredentialPublicKeyVO convert(MappingContext<CredentialPublicKey, CredentialPublicKeyVO> context) {
        CredentialPublicKey source = context.getSource();
        CredentialPublicKeyVO destination = context.getDestination();

        if (source == null) {
            return null;
        }
        if (source.getClass() == RSACredentialPublicKey.class) {
            if (destination == null) {
                destination = new RSCredentialPublicKeyVO();
            }
            context.getMappingEngine().map(context.create((RSACredentialPublicKey) source, (RSCredentialPublicKeyVO)destination));
        } else if (source.getClass() == ECCredentialPublicKey.class) {
            if (destination == null) {
                destination = new ECCredentialPublicKeyVO();
            }
            context.getMappingEngine().map(context.create((ECCredentialPublicKey) source, (ECCredentialPublicKeyVO)destination));
        } else {
            throw new IllegalArgumentException();
        }
        return destination;
    }
}
