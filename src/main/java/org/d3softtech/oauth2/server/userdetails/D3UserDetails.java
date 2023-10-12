package org.d3softtech.oauth2.server.userdetails;

import java.util.List;
import java.util.Set;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

@Getter
public class D3UserDetails extends User {

    private final Integer userId;
    private final boolean isPasswordChangeRequired;
    private final Set<String> roles;
    private Short operatorId;

    public D3UserDetails(Integer userId, String username, String password, List<GrantedAuthority> authorities,
        Short operatorId, boolean isPasswordChangeRequired, Set<String> roles) {
        super(username, password, authorities);
        this.userId = userId;
        this.operatorId = operatorId;
        this.isPasswordChangeRequired = isPasswordChangeRequired;
        this.roles = roles;
    }
}
