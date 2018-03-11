package net.sharplab.springframework.security.webauthn.sample.domain.entity;

import lombok.Data;

import javax.persistence.*;
import java.io.Serializable;
import java.util.List;

/**
 * ユーザーモデル
 */
@Data
@Entity
@Table(name = "m_user")
public class UserEntity implements Serializable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;
    private byte[]  userHandle;
    private String  firstName;
    private String  lastName;
    private String  emailAddress;

    @ManyToMany
    @JoinTable(
            name="r_user_group",
            joinColumns = {@JoinColumn(name = "group_id", referencedColumnName = "id")},
            inverseJoinColumns = {@JoinColumn(name = "user_id", referencedColumnName = "id")}

    )
    private List<GroupEntity> groups;

    @ManyToMany
    @JoinTable(
            name="r_user_authority",
            joinColumns = {@JoinColumn(name = "authority_id", referencedColumnName = "id")},
            inverseJoinColumns = {@JoinColumn(name = "user_id", referencedColumnName = "id")}

    )
    private List<AuthorityEntity> authorities;

    @OneToMany(fetch = FetchType.EAGER, mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<AuthenticatorEntity> authenticators;

    private String password;

    private boolean locked;

    @Column(name = "pwauth_allowed")
    private boolean passwordAuthenticationAllowed;

    /**
     * アカウントの文字列表現。E-Mailアドレス
     * @return アカウントのE-Mailアドレス
     */
    @Override
    public String toString(){
        return emailAddress;
    }

}
