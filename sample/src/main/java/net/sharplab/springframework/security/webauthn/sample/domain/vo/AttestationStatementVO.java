package net.sharplab.springframework.security.webauthn.sample.domain.vo;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;

import java.io.Serializable;

/**
 * AttestationStatementVO
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, property = "format")
@JsonSubTypes({
        @JsonSubTypes.Type(name = "fido-u2f", value = FIDOU2FAttestationStatementVO.class),
        @JsonSubTypes.Type(name = "packed", value = PackedAttestationStatementVO.class),
        @JsonSubTypes.Type(name = "none", value = NoneAttestationStatementVO.class)
})
public interface AttestationStatementVO extends Serializable {

    @JsonIgnore
    String getFormat();
}
