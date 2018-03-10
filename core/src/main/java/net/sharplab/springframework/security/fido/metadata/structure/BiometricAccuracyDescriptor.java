package net.sharplab.springframework.security.fido.metadata.structure;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Created by ynojima on 2017/09/08.
 */
public class BiometricAccuracyDescriptor {

    @JsonProperty
    private double  FAR;
    @JsonProperty
    private double  FRR;
    @JsonProperty
    private double  EER;
    @JsonProperty
    private double  FAAR;
    @JsonProperty
    private Integer maxReferenceDataSets;
    @JsonProperty
    private Integer maxRetries;
    @JsonProperty
    private Integer blockSlowdown;
}
