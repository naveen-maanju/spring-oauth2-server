package org.d3softtech.oauth2.server.userdetails;

import java.util.List;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

@Getter
public class D3UserDetails extends User {

  private final Integer userId;
  private final boolean isPasswordChangeRequired;
  private final List<String> roles;
  private final String ssn;
  private final String email;

  public D3UserDetails(Integer userId, String username, String password, List<GrantedAuthority> authorities,
      String ssn, String email, boolean isPasswordChangeRequired, List<String> roles) {
    super(username, password, authorities);
    this.userId = userId;
    this.ssn = ssn;
    this.email = email;
    this.isPasswordChangeRequired = isPasswordChangeRequired;
    this.roles = roles;
  }
}
