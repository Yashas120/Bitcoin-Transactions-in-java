package hashing;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashLib {

    private static MessageDigest sha256;

    // generated password is stored encrypted (using also user name for hashing)
    public synchronized static String encrypt(String hash) {
        try {

            StringBuilder builder = new StringBuilder();
            builder.append(hash);

            // first time , encrypt user name , password and static key
            String encryptedCredentials = encryptionIterator(builder.toString());
           return encryptedCredentials;
        } 

        catch (Exception e) {
            e.printStackTrace();
        }

        return "";
    }

    private static String encryptionIterator(String content) {
        try {
            sha256 = MessageDigest.getInstance("SHA-256");
            // append the static key to each iteration
            byte[] passBytes = (content).getBytes();
            sha256.reset();
            byte[] digested = sha256.digest(passBytes);
            StringBuffer sb = new StringBuffer();
            for (int i = 0; i < digested.length; i++) {
                sb.append(String.format("%02x", 0xff & digested[i]));
            }

            return sb.toString();
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
        }

        return "";
    }
}