package org.carlspring.strongbox.configuration;

import javax.inject.Inject;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.util.Base64Utils;


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
    void encodeAndMatch()
    {
        String text = "password12";
        String base64EncodedString = Base64Utils.encodeToString(text.getBytes());

        String normalEncode = passwordEncoder.encode(text);
        String base64Encode = passwordEncoder.encode(base64EncodedString);

        Assertions.assertTrue(passwordEncoder.matches(text, normalEncode));
        Assertions.assertTrue(passwordEncoder.matches(text, base64Encode));
    }
}
