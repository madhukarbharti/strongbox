package org.carlspring.strongbox.configuration;

import javax.inject.Inject;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;

@SpringBootTest
@ActiveProfiles(profiles = "test")
@ContextConfiguration
class StrongboxDelegatingPasswordEncoderTest
{

    @org.springframework.context.annotation.Configuration
    @ComponentScan(basePackages = { "org.carlspring.strongbox.security",
                                    "org.carlspring.strongbox.testing",
                                    "org.carlspring.strongbox.configuration" })
    public static class SpringConfig
    {

    }

    @Inject
    private PasswordEncoder passwordEncoder;

    @Test
    void testNullEncodeAndMatch()
    {
        Assertions.assertThrows(NullPointerException.class, () -> passwordEncoder.encode(null));
        Assertions.assertTrue(passwordEncoder.matches(null, null));
    }

    @Test
    void testHashContainsBase64EncodePassword()
    {
        String base64HashedString = "{MD5}X03MO1qnZdYdgyfeuILPmQ==";
        Assertions.assertTrue(passwordEncoder.matches("password", base64HashedString));
    }

    @Test
    void testHashWithoutBase64EncodePassword()
    {
        String hashedString = "{bcrypt}$2a$10$lpwlxyjvXKzN1ccCrw2PBuZx.eVesWbfmTbsrCboMU.gsNWVcZWMi";
        Assertions.assertTrue(passwordEncoder.matches("password", hashedString));
    }

    @Test
    void testEncodeDecodeTest()
    {
        String text = "password-12";
        String hashedString = passwordEncoder.encode(text);
        Assertions.assertTrue(passwordEncoder.matches(text, hashedString));
    }
}

