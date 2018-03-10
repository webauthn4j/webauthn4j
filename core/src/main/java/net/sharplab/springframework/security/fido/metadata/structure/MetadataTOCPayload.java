package net.sharplab.springframework.security.fido.metadata.structure;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.LocalDate;
import java.util.List;

/**
 * Created by ynojima on 2017/09/08.
 */
public class MetadataTOCPayload {
    @JsonProperty
    private LocalDate nextUpdate;
    @JsonProperty
    private Integer no;
    @JsonProperty
    private List<MetadataTOCPayloadEntry> entries;

    public LocalDate getNextUpdate() {
        return nextUpdate;
    }

    public Integer getNo() {
        return no;
    }

    public List<MetadataTOCPayloadEntry> getEntries() {
        return entries;
    }

}
