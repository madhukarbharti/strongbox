package org.carlspring.strongbox.configuration;

import java.util.Base64;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.crypto.codec.Utf8;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * This class encodes given raw String or Base64 encoded string.
 * If given string is Base64 Encoded it will attempt to decode the password and finally delegate it to the password encoder.
 * This handles all possible cases
 * <p>
 * {ALG}md5/sha1/bcrypt(mypassword)
 * {ALG}base64.encode(md5/sha1/bcrypt(mypassword))
 * base64.encode({ALG}md5/sha1/bcrypt(mypassword))
 *
 * @author mbharti
 * @date 07/10/20
 */
@Component
public class Base64PasswordEncoderDelegate
        implements PasswordEncoder
{

    private static final String PREFIX = "{";

    private static final String SUFFIX = "}";

    private final PasswordEncoder passwordEncoder;

    private static final Logger logger = LoggerFactory.getLogger(Base64PasswordEncoderDelegate.class);


    /**
     * Constructs PasswordEncoder with given PasswordEncoder
     *
     * @param passwordEncoder
     */
    public Base64PasswordEncoderDelegate(PasswordEncoder passwordEncoder)
    {
        this.passwordEncoder = passwordEncoder;
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
        boolean matches = matchesEncodedPassword(rawCharSequence, encodedString);

        // When the default password encoder does not match - attempt to decode password and retry.
        // Edge case for https://github.com/strongbox/strongbox/issues/1840}
        if (!matches)
        {
            matches = matchesBase64EncodedPasswordAfterAlgorithm(rawCharSequence, encodedString);

            if (!matches)
            {
                matches = matchesBase64EncodedPassword(rawCharSequence, encodedString);
            }
        }

        return matches;
    }

    private boolean matchesEncodedPassword(CharSequence rawCharSequence,
                                           String encodedString)
    {
        try
        {
            return passwordEncoder.matches(rawCharSequence, encodedString);
        }
        catch (Exception e)
        {
            logger.warn("Failed to match password");
            return false;
        }
    }


    private boolean matchesBase64EncodedPasswordAfterAlgorithm(CharSequence rawCharSequence,
                                                               CharSequence prefixEncodedPassword)
    {
        if (prefixEncodedPassword == null || rawCharSequence == null)
        {
            return false;
        }

        try
        {
            String prefixEncodedPasswordString = prefixEncodedPassword.toString();

            String algorithmUsed = extractId(prefixEncodedPasswordString);

            String base64DecodedPasswordAfterAlgorithm;

            String extractBase64EncodedHash = prefixEncodedPasswordString;

            if (StringUtils.isNotEmpty(algorithmUsed))
            {
                extractBase64EncodedHash = extractEncodedPassword(prefixEncodedPasswordString);

                base64DecodedPasswordAfterAlgorithm =
                        PREFIX + algorithmUsed + SUFFIX + decodeBase64EncodedHashWithHex(extractBase64EncodedHash);
            }
            else
            {
                base64DecodedPasswordAfterAlgorithm = decodeBase64EncodedHashWithHex(extractBase64EncodedHash);
            }

            return passwordEncoder.matches(rawCharSequence, base64DecodedPasswordAfterAlgorithm);
        }
        catch (Exception e)
        {
            logger.warn("Failed to match password after decoding base64encoded hash after algorithm");
            return false;
        }
    }

    private boolean matchesBase64EncodedPassword(CharSequence rawCharSequence,
                                                 CharSequence prefixEncodedPassword)
    {
        if (prefixEncodedPassword == null || rawCharSequence == null)
        {
            return false;
        }
        try
        {
            String base64DecodedPassword = new String(
                    Base64.getDecoder().decode(Utf8.encode(prefixEncodedPassword.toString())));

            return passwordEncoder.matches(rawCharSequence, base64DecodedPassword);
        }
        catch (Exception e)
        {
            logger.warn("Failed to match password after decoding base64 hash included algorithm");
            return false;
        }
    }

    private String decodeBase64EncodedHashWithHex(String base64EncodedHash)
    {
        try
        {
            return new String(Hex.encode(Base64.getDecoder().decode(Utf8.encode(base64EncodedHash))));
        }
        catch (Exception ex)
        {
            logger.warn("Failed to do Base64Decoding " + ex.getMessage());
        }

        return base64EncodedHash;
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
