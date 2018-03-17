package net.sharplab.springframework.security.webauthn.sample.app.web;

import lombok.Data;
import net.sharplab.springframework.security.webauthn.client.CollectedClientData;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

/**
 * Created by ynojima on 2017/08/20.
 */
@Data
public class CollectedClientDataForm {

    @NotNull
    @Valid
    private CollectedClientData collectedClientData;

    @NotNull
    private String clientDataBase64;

}
