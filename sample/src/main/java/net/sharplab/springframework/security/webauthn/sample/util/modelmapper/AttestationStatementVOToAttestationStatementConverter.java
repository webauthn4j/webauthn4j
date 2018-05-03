package net.sharplab.springframework.security.webauthn.sample.util.modelmapper;

import com.webauthn4j.attestation.statement.AttestationStatement;
import com.webauthn4j.attestation.statement.FIDOU2FAttestationStatement;
import com.webauthn4j.attestation.statement.NoneAttestationStatement;
import com.webauthn4j.attestation.statement.PackedAttestationStatement;
import net.sharplab.springframework.security.webauthn.sample.domain.vo.AttestationStatementVO;
import net.sharplab.springframework.security.webauthn.sample.domain.vo.FIDOU2FAttestationStatementVO;
import net.sharplab.springframework.security.webauthn.sample.domain.vo.NoneAttestationStatementVO;
import net.sharplab.springframework.security.webauthn.sample.domain.vo.PackedAttestationStatementVO;
import org.modelmapper.Converter;
import org.modelmapper.spi.MappingContext;

/**
 * Converter which converts from {@link AttestationStatementVO} to {@link AttestationStatement}
 */
public class AttestationStatementVOToAttestationStatementConverter implements Converter<AttestationStatementVO, AttestationStatement> {

    @Override
    public AttestationStatement convert(MappingContext<AttestationStatementVO, AttestationStatement> context) {
        AttestationStatementVO source = context.getSource();
        AttestationStatement destination = context.getDestination();
        if (source == null) {
            return null;
        }
        if (source.getClass() == PackedAttestationStatementVO.class) {
            if (destination == null) {
                destination = new PackedAttestationStatement();
            }
            context.getMappingEngine().map(context.create((PackedAttestationStatementVO) source, destination));
        } else if (source.getClass() == FIDOU2FAttestationStatementVO.class) {
            if (destination == null) {
                destination = new FIDOU2FAttestationStatement();
            }
            context.getMappingEngine().map(context.create((FIDOU2FAttestationStatementVO) source, destination));
        } else if (source.getClass() == NoneAttestationStatementVO.class) {
            if (destination == null) {
                destination = new NoneAttestationStatement();
            }
            context.getMappingEngine().map(context.create((NoneAttestationStatementVO) source, destination));
        } else {
            throw new IllegalArgumentException();
        }
        return destination;
    }

}
