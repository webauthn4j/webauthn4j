package net.sharplab.springframework.security.webauthn.sample.app.web.admin;

import lombok.Data;
import javax.validation.constraints.NotEmpty;

/**
 * グループ管理フォーム
 */
@Data
public class GroupForm {

    @NotEmpty
    private String  groupName;

}
