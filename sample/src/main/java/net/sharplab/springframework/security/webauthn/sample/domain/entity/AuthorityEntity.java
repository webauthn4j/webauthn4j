package net.sharplab.springframework.security.webauthn.sample.domain.entity;

import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;

import javax.persistence.*;
import java.util.List;

/**
 * 権限モデル
 */
@SuppressWarnings("WeakerAccess")
@Entity
@Getter
@Setter
@Table(name = "m_authority")
public class AuthorityEntity implements GrantedAuthority {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @ManyToMany
    @JoinTable(
            name="r_user_authority",
            joinColumns = {@JoinColumn(name = "user_id", referencedColumnName = "id")},
            inverseJoinColumns = {@JoinColumn(name = "authority_id", referencedColumnName = "id")}
    )
    private List<UserEntity> users;

    @ManyToMany
    @JoinTable(
            name="r_group_authority",
            joinColumns = {@JoinColumn(name = "group_id", referencedColumnName = "id")},
            inverseJoinColumns = {@JoinColumn(name = "authority_id", referencedColumnName = "id")}

    )
    private List<GroupEntity> groups;

    @Column(name = "authority")
    private String authority;

    public AuthorityEntity(){
        //NOP
    }

    public AuthorityEntity(int id, String authority) {
        this.id = id;
        this.authority = authority;
    }

    @Override
    public String toString(){
        return authority;
    }
}
