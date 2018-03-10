package net.sharplab.springframework.security.fido.metadata.structure;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Created by ynojima on 2017/09/08.
 */
public class CodeAccuracyDescriptor {

    @JsonProperty
    private Integer base;
    @JsonProperty
    private Integer minLength;
    @JsonProperty
    private Integer maxRetries;
    @JsonProperty
    private Integer blockSlowdown;
}
