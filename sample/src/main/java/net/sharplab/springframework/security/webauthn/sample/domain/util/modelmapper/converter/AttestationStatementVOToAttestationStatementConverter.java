package net.sharplab.springframework.security.webauthn.sample.domain.util.modelmapper.converter;

import net.sharplab.springframework.security.webauthn.attestation.statement.NoneAttestationStatement;
import net.sharplab.springframework.security.webauthn.attestation.statement.WebAuthnAttestationStatement;
import net.sharplab.springframework.security.webauthn.attestation.statement.FIDOU2FAttestationStatement;
import net.sharplab.springframework.security.webauthn.attestation.statement.PackedAttestationStatement;
import net.sharplab.springframework.security.webauthn.sample.domain.vo.AttestationStatementVO;
import net.sharplab.springframework.security.webauthn.sample.domain.vo.FIDOU2FAttestationStatementVO;
import net.sharplab.springframework.security.webauthn.sample.domain.vo.NoneAttestationStatementVO;
import net.sharplab.springframework.security.webauthn.sample.domain.vo.PackedAttestationStatementVO;
import org.modelmapper.Converter;
import org.modelmapper.spi.MappingContext;

/**
 * Converter which converts from {@link AttestationStatementVO} to {@link WebAuthnAttestationStatement}
 */
public class AttestationStatementVOToAttestationStatementConverter implements Converter<AttestationStatementVO, WebAuthnAttestationStatement> {

    @Override
    public WebAuthnAttestationStatement convert(MappingContext<AttestationStatementVO, WebAuthnAttestationStatement> context) {
        AttestationStatementVO source = context.getSource();
        WebAuthnAttestationStatement destination = context.getDestination();
        if (source == null) {
            return null;
        }
        if (source.getClass() == PackedAttestationStatementVO.class) {
            if (destination == null) {
                destination = new PackedAttestationStatement();
            }
            context.getMappingEngine().map(context.create((PackedAttestationStatementVO) source, destination));
        }
        else if (source.getClass() == FIDOU2FAttestationStatementVO.class) {
            if (destination == null) {
                destination = new FIDOU2FAttestationStatement();
            }
            context.getMappingEngine().map(context.create((FIDOU2FAttestationStatementVO) source, destination));
        }
        else if(source.getClass() == NoneAttestationStatementVO.class){
            if (destination == null) {
                destination = new NoneAttestationStatement();
            }
            context.getMappingEngine().map(context.create((NoneAttestationStatementVO) source, destination));
        }
        else {
            throw new IllegalArgumentException();
        }
        return destination;
    }

}
