package net.sharplab.springframework.security.webauthn.sample.domain.model;

import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;

import java.util.List;

/**
 * 権限モデル
 */
@Getter
@Setter
public class Authority implements GrantedAuthority {

    private int id;

    private List<User> users;
    private List<Group> groups;

    private String authority;

    public Authority() {
        //NOP
    }

    public Authority(int id) {
        this.id = id;
    }

    public Authority(String authority) {
        this.authority = authority;
    }

    public Authority(int id, String authority) {
        this.id = id;
        this.authority = authority;
    }

    public Authority(int id, String authority, List<User> users, List<Group> groups) {
        this.id = id;
        this.authority = authority;
        this.users = users;
        this.groups = groups;
    }


    @Override
    public String toString() {
        return authority;
    }
}
