package net.sharplab.springframework.security.webauthn.sample.domain.model;

import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.util.List;

/**
 * グループモデル
 */
@Setter
@Getter
public class Group implements Serializable {

    private Integer id;
    private String groupName;

    private List<User> users;
    private List<Authority> authorities;

    public Group() {
        //NOP
    }

    public Group(String group) {
        groupName = group;
    }

    public Group(int id) {
        this.id = id;
    }
}
