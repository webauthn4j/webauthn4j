package net.sharplab.springframework.security.fido.metadata.structure;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.math.BigInteger;

/**
 * Created by ynojima on 2017/09/08.
 */
public class PatternAccuracyDescriptor {

    @JsonProperty
    private BigInteger minComplexity;
    @JsonProperty
    private Integer maxRetries;
    @JsonProperty
    private Integer blockSlowdown;
}
