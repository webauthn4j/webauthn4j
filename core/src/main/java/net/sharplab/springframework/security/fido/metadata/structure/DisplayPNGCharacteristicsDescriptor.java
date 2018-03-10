package net.sharplab.springframework.security.fido.metadata.structure;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.math.BigInteger;
import java.util.List;

/**
 * Created by ynojima on 2017/09/08.
 */
public class DisplayPNGCharacteristicsDescriptor {

    @JsonProperty
    private BigInteger width;
    @JsonProperty
    private BigInteger height;
    @JsonProperty
    private Short      bitDepth;
    @JsonProperty
    private Short      colorType;
    @JsonProperty
    private Short      compression;
    @JsonProperty
    private Short      filter;
    @JsonProperty
    private Short      interlace;
    @JsonProperty
    private List<RGBPalletteEntry> plte;
}
