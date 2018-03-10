package net.sharplab.springframework.security.fido.metadata.structure;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.math.BigInteger;

/**
 * Created by ynojima on 2017/09/08.
 */
public class VerificationMethodDescriptor {
    @JsonProperty
    private BigInteger userVerification;
    @JsonProperty
    private CodeAccuracyDescriptor      caDesc;
    @JsonProperty
    private BiometricAccuracyDescriptor baDesc;
    @JsonProperty
    private PatternAccuracyDescriptor   paDesc;
}
