package org.carlspring.strongbox.configuration;

import javax.annotation.PostConstruct;

import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.util.Base64Utils;

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

    private PasswordEncoder passwordEncoder;

    @PostConstruct
    private void init()
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
        return passwordEncoder.encode(getDecodedString(rawCharSequence));
    }

    /**
     * Verify the encoded password obtained from storage matches the submitted raw password after it too is encoded.
     * Returns true if the passwords match, false if they do not. The stored password itself is never decoded.
     * In case given rawCharSequence is Base64 encoded, then it decode it first then verifies.
     *
     * @param rawCharSequence Raw String or Base64 encoded String
     * @param encodedString   Encoded String
     * @return true if the passwords match
     * false if the password do not match
     */
    @Override
    public boolean matches(CharSequence rawCharSequence,
                           String encodedString)
    {
        return passwordEncoder.matches(getDecodedString(rawCharSequence), encodedString);
    }

    private String getDecodedString(CharSequence rawCharSequence)
    {
        if (rawCharSequence == null)
        {
            return null;
        }

        String rawString = rawCharSequence.toString();

        try
        {
            //May throw IllegalArgumentException if raw string contains invalid Base64 characters
            String base64DecodedString = new String(Base64Utils.decodeFromString(rawString));

            String base64EncodedString = Base64Utils.encodeToString(base64DecodedString.getBytes());

            if (rawString.equals(base64EncodedString))
            {
                return base64DecodedString;
            }
        }
        catch (IllegalArgumentException e)
        {
            return rawString;
        }

        return rawString;
    }
}
