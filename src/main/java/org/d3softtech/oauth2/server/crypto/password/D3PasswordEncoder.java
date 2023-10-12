package org.d3softtech.oauth2.server.crypto.password;

import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.crypto.hash.Sha256Hash;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class D3PasswordEncoder implements PasswordEncoder {

    @Override
    public String encode(CharSequence rawPassword) {
        if (rawPassword == null) {
            throw new IllegalArgumentException("rawPassword cannot be null");
        }
        return (new Sha256Hash(rawPassword, "hCc1lYbGxjaTU6Mz")).toBase64();
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        if (rawPassword == null) {
            throw new IllegalArgumentException("rawPassword cannot be null");
        }
        if (encodedPassword == null || encodedPassword.length() == 0) {
            log.warn("Empty encoded password");
            return false;
        }
        return encode(rawPassword).equals(encodedPassword);
    }
}
