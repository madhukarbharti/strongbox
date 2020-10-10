package org.carlspring.strongbox.configuration;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

class Base64PasswordEncoderDelegateTest
{

    private final PasswordEncoder passwordEncoder = new Base64PasswordEncoderDelegate(
            PasswordEncoderFactories.createDelegatingPasswordEncoder());

    @Test
    void testNullEncodeAndMatch()
    {
        Assertions.assertThrows(NullPointerException.class, () -> passwordEncoder.encode(null));
        Assertions.assertTrue(passwordEncoder.matches(null, null));
    }

    @Test
    void testHashContainsBase64EncodePassword()
    {
        //{MD5}Base64.encoded(...)
        String base64HashedString = "{MD5}X03MO1qnZdYdgyfeuILPmQ==";
        Assertions.assertTrue(passwordEncoder.matches("password", base64HashedString));
    }

    @Test
    void testHashWithoutBase64EncodePassword()
    {
        //{bcrypt}hash-password
        String hashedString = "{bcrypt}$2a$10$lpwlxyjvXKzN1ccCrw2PBuZx.eVesWbfmTbsrCboMU.gsNWVcZWMi";
        Assertions.assertTrue(passwordEncoder.matches("password", hashedString));
    }

    @Test
    void testBase64EEncodedHashWithAlgorithms()
    {
        //Base64.encoded({bcrypt}$2a$10$lpwlxyjvXKzN1ccCrw2PBuZx.eVesWbfmTbsrCboMU.gsNWVcZWMi)
        String hashedString = "e2JjcnlwdH0kMmEkMTAkbHB3bHh5anZYS3pOMWNjQ3J3MlBCdVp4LmVWZXNXYmZtVGJzckNib01VLmdzTldWY1pXTWk=";

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

