package org.carlspring.strongbox.configuration;

import java.util.Base64;

import org.apache.commons.lang3.StringUtils;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.crypto.codec.Utf8;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * This class encodes given raw String or Base64 encoded string.
 * If given string is Base64 Encoded it will attempt to decode the password and finally delegate it to the password encoder.
 *
 * @author mbharti
 * @date 07/10/20
 */
@Component
public class StrongboxDelegatingPasswordEncoder
        implements PasswordEncoder
{

    private static final String PREFIX = "{";

    private static final String SUFFIX = "}";

    private PasswordEncoder passwordEncoder;


    public StrongboxDelegatingPasswordEncoder()
    {
        passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    /**
     * This Encodes the raw password. In case given rawCharSequence is Base64 encoded,
     * then it will decode and then encode the decoded string.
     *
     * @param rawCharSequence Raw String or Base64 encoded String
     * @return Encoded String
     */
    @Override
    public String encode(CharSequence rawCharSequence)
    {
        return passwordEncoder.encode(rawCharSequence);
    }

    /**
     * Verify the encoded password obtained from storage matches the submitted raw password after it too is encoded.
     * Returns true if the passwords match, false if they do not. The stored password itself is never decoded.
     * In case given rawCharSequence is Base64 encoded, then it decode it first then verifies.
     *
     * @param rawCharSequence Raw password
     * @param encodedString   Encoded Hash String or hash containing Base64 encoded String
     * @return true if the passwords match
     * false if the password do not match
     */
    @Override
    public boolean matches(CharSequence rawCharSequence,
                           String encodedString)
    {
        boolean isMatches = passwordEncoder.matches(rawCharSequence, encodedString);

        if (isMatches)
        {
            return true;
        }

        return passwordEncoder.matches(rawCharSequence, decodeBase64PasswordHash(encodedString));
    }


    private String decodeBase64PasswordHash(CharSequence prefixEncodedPassword)
    {
        if (prefixEncodedPassword == null)
        {
            return null;
        }

        String prefixEncodedPasswordString = prefixEncodedPassword.toString();
        String algorithmUsed = extractId(prefixEncodedPasswordString);

        try
        {
            String encodedPassword = prefixEncodedPasswordString;

            if (StringUtils.isNotEmpty(algorithmUsed))
            {
                encodedPassword = extractEncodedPassword(prefixEncodedPasswordString);
            }

            return PREFIX + algorithmUsed + SUFFIX +
                   new String(Hex.encode(Base64.getDecoder().decode(Utf8.encode(encodedPassword))));
        }
        catch (Exception ex)
        {
            return prefixEncodedPasswordString;
        }
    }

    private String extractEncodedPassword(String prefixEncodedPassword)
    {
        int start = prefixEncodedPassword.indexOf(SUFFIX);

        return prefixEncodedPassword.substring(start + 1);
    }

    private String extractId(String prefixEncodedPassword)
    {
        int start = prefixEncodedPassword.indexOf(PREFIX);

        if (start != 0)
        {
            return StringUtils.EMPTY;
        }

        int end = prefixEncodedPassword.indexOf(SUFFIX, start);

        if (end < 0)
        {
            return StringUtils.EMPTY;
        }

        return prefixEncodedPassword.substring(start + 1, end);
    }
}
