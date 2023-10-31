package org.d3softtech.oauth2.server.crypto.password;


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@ExtendWith(SpringExtension.class)
public class D3PasswordEncoderTest {

    private D3PasswordEncoder d3PasswordEncoder = new D3PasswordEncoder();

    @Test
    void encode_ShouldEncodeThePassword_AndMatchWithEveryIteration() {
        String password = "R3ferenc$";
        String hashedPassword = d3PasswordEncoder.encode(password);
        System.out.println(hashedPassword);
        assertNotEquals(password, hashedPassword);
        assertEquals(hashedPassword, d3PasswordEncoder.encode("R3ferenc$"));
    }
}
