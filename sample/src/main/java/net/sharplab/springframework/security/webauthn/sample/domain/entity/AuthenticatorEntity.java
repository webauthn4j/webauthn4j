package net.sharplab.springframework.security.webauthn.sample.domain.entity;

import lombok.Data;
import net.sharplab.springframework.security.webauthn.sample.domain.vo.AttestedCredentialDataVO;
import net.sharplab.springframework.security.webauthn.sample.domain.vo.AttestationStatementVO;
import net.sharplab.springframework.security.webauthn.sample.infrastructure.util.jpa.converter.AttestationStatementVOConverter;

import javax.persistence.*;
import java.io.Serializable;

/**
 * AuthenticatorEntity
 */
@Entity
@Data
@Table(name = "m_authenticator")
public class AuthenticatorEntity implements Serializable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    private String name;

    @ManyToOne
    private UserEntity user;

    @Column(columnDefinition = "blob")
    private byte[] rpIdHash;

    private long counter;

    @Embedded
    private AttestedCredentialDataVO attestedCredentialData;

    //TODO: extensions?

    public String getFormat() {
        return attestationStatement.getFormat();
    }

    @Column(columnDefinition = "text")
    @Convert(converter = AttestationStatementVOConverter.class)
    private AttestationStatementVO attestationStatement;
}
