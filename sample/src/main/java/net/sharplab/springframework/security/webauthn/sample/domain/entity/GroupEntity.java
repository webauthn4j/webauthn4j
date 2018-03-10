package net.sharplab.springframework.security.webauthn.sample.domain.entity;

import lombok.Data;

import javax.persistence.*;
import java.io.Serializable;
import java.util.List;

/**
 * グループモデル
 */
@Data
@Entity
@Table(name = "m_group")
public class GroupEntity implements Serializable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;
    @Column(name = "group_name")
    private String  groupName;

    @ManyToMany
    @JoinTable(
            name="r_user_group",
            joinColumns = {@JoinColumn(name = "user_id", referencedColumnName = "id")},
            inverseJoinColumns = {@JoinColumn(name = "group_id", referencedColumnName = "id")}

    )
    private List<UserEntity> users;

    @ManyToMany
    @JoinTable(
            name="r_group_authority",
            joinColumns = {@JoinColumn(name = "authority_id", referencedColumnName = "id")},
            inverseJoinColumns = {@JoinColumn(name = "group_id", referencedColumnName = "id")}

    )
    private List<AuthorityEntity> authorities;

    /**
     * グループの文字列表現。グループ名
     * @return アカウントのグループ名
     */
    @Override
    public String toString(){
        return groupName;
    }


}
