package net.sharplab.springframework.security.fido.metadata.structure;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Created by ynojima on 2017/09/08.
 */
public class Version {
    @JsonProperty
    private Integer major;
    @JsonProperty
    private Integer minor;
}
