package net.sharplab.springframework.security.webauthn.sample.domain.model;

import lombok.Getter;
import lombok.Setter;
import net.sharplab.springframework.security.webauthn.userdetails.WebAuthnUserDetails;

import java.util.List;

/**
 * ユーザーモデル
 */
@Getter
@Setter
public class User implements WebAuthnUserDetails {

    private Integer id;
    private byte[]  userHandle;
    private String  firstName;
    private String  lastName;
    private String  emailAddress;

    private List<Authority> authorities;

    private List<Group> groups;

    private String password;

    private List<Authenticator> authenticators;

    private boolean locked;

    private boolean passwordAuthenticationAllowed = false;

    public User(){
        //NOP
    }

    public User(int id){
        this.id = id;
    }

    public User(Integer id, byte[] userHandle, String firstName, String lastName, String emailAddress, List<Authority> authorities, List<Group> groups, List<Authenticator> authenticators, boolean locked, boolean passwordAuthenticationAllowed){
        this.id = id;
        this.userHandle = userHandle;
        this.firstName = firstName;
        this.lastName = lastName;
        this.emailAddress = emailAddress;
        this.authorities = authorities;
        this.groups = groups;
        this.authenticators = authenticators;
        this.locked = locked;
        this.passwordAuthenticationAllowed = passwordAuthenticationAllowed;
    }

    /**
     * 姓名を返却する
     * @return 姓名
     */
    @SuppressWarnings("WeakerAccess")
    public String getFullname(){
        return firstName + " " + lastName;
    }

    /**
     * ユーザー名を返却する
     * @return ユーザー名
     */
    @Override
    public String getUsername() {
        return getEmailAddress();
    }

    @Override
    public List<Authenticator> getAuthenticators() { return this.authenticators; }

    @Override
    public boolean isPasswordAuthenticationAllowed() {
        return this.passwordAuthenticationAllowed;
    }

    @Override
    public void setPasswordAuthenticationAllowed(boolean passwordAuthenticationAllowed) {
        this.passwordAuthenticationAllowed = passwordAuthenticationAllowed;
    }

    /**
     * アカウントが有効期限内か
     * @return アカウントが有効期限内の場合<code>true</code>
     */
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    /**
     * アカウントがロックされていないか
     * @return アカウントがロックされていない場合<code>true</code>
     */
    @Override
    public boolean isAccountNonLocked() {
        return !locked;
    }

    /**
     * アカウントの認証情報が有効か
     * @return アカウントの認証情報が有効の場合<code>true</code>
     */
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    /**
     * アカウントが有効か
     * @return アカウントが有効の場合<code>true</code>
     */
    @Override
    public boolean isEnabled() {
        return true;
    }

}
