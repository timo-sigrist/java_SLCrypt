package ch.zhaw.securitylab.slcrypt.encrypt;

import java.io.InputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import ch.zhaw.securitylab.slcrypt.FileHeader;
import ch.zhaw.securitylab.slcrypt.Helpers;
import java.io.ByteArrayOutputStream;
import java.security.spec.PKCS8EncodedKeySpec;

public class HybridEncryptionImpl extends HybridEncryption {

    @Override
    protected byte[] generateSecretKey(String cipherAlgorithm, int keyLength) {
        try {
            String cipherName = Helpers.getCipherName(cipherAlgorithm);
            
            if (cipherName.equals("SEED")) {
                byte[] key = new byte[16];
                SecureRandom random = new SecureRandom();
                random.nextBytes(key);
                return key;
            }
            
            KeyGenerator keyGen = KeyGenerator.getInstance(cipherName);
            keyGen.init(keyLength);
            SecretKey secretKey = keyGen.generateKey();
            return secretKey.getEncoded();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Error generating secret key", e);
        }
    }

    @Override
    protected byte[] encryptSecretKey(byte[] secretKey, InputStream certificateEncrypt) {
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            Certificate certificate = factory.generateCertificate(certificateEncrypt);
            PublicKey publicKey = certificate.getPublicKey();

            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            return cipher.doFinal(secretKey);
        } catch (Exception e) {
            throw new RuntimeException("Error encrypting secret key", e);
        }
    }

    @Override
protected FileHeader generateFileHeader(String cipherAlgorithm, char authIntType, 
                                        String authIntAlgorithm, InputStream certificateVerify, 
                                        byte[] encryptedSecretKey) {
    try {
        
        FileHeader header = new FileHeader();
        header.setCipherAlgorithm(cipherAlgorithm);

        // Generate and set IV, or set to an empty byte array if IV is not required
        byte[] iv;
        if (Helpers.hasIV(cipherAlgorithm)) {
            iv = new byte[Helpers.getIVLength(cipherAlgorithm)];
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);
        } else {
            iv = new byte[0]; // No IV required
        }
        header.setIV(iv);
        
        header.setAuthIntType(authIntType);
        header.setAuthIntAlgorithm(authIntAlgorithm);
       
        // read cert
        byte[] certificateBytes;
        if (certificateVerify != null && authIntType == Helpers.SIGNATURE) {
            ByteArrayOutputStream certByteOS = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = certificateVerify.read(buffer)) != -1) {
                certByteOS.write(buffer, 0, bytesRead);  
            }
            certificateBytes = certByteOS.toByteArray();
        } else {
            certificateBytes = new byte[0]; 
        }
        header.setCertificate(certificateBytes);

        header.setEncryptedSecretKey(encryptedSecretKey);

        return header;
    } catch (Exception e) {
        throw new RuntimeException("Error generating file header", e);
    }
}


    @Override
    protected byte[] encryptDocument(InputStream document, FileHeader fileHeader, byte[] secretKey) {
        try {
            String cipherAlgorithm = fileHeader.getCipherAlgorithm();
            Cipher cipher = Cipher.getInstance(cipherAlgorithm);
            
            SecretKeySpec keySpec = new SecretKeySpec(secretKey, Helpers.getCipherName(cipherAlgorithm));
            byte[] iv = fileHeader.getIV();
            
            if (Helpers.isCBC(cipherAlgorithm)){
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
                
            } else if (Helpers.isCTR(cipherAlgorithm)) {
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

            } else if (Helpers.isGCM(cipherAlgorithm)) {
                GCMParameterSpec gcmSpec = new GCMParameterSpec(Helpers.AUTH_TAG_LENGTH, iv);
                cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
                cipher.updateAAD(fileHeader.encode()); // Add file header as AAD
                
            } else if (Helpers.isCHACHA20(cipherAlgorithm)) {
                ChaCha20ParameterSpec chaChaSpec = new ChaCha20ParameterSpec(iv, 1);
                cipher.init(Cipher.ENCRYPT_MODE, keySpec, chaChaSpec); // Counter = 1
                
            } else if (Helpers.hasIV(cipherAlgorithm)){
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
                
            } else {
                cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            }

            ByteArrayOutputStream encryptedOutput = new ByteArrayOutputStream();

            // Read data from CipherInputStream and write to ByteArrayOutputStream
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = document.read(buffer)) != -1) {
                byte[] output = cipher.update(buffer, 0, bytesRead);
                if (output != null) {
                    encryptedOutput.write(output);
                }                
            }
            byte[] outputFinal = cipher.doFinal();
            if (outputFinal != null) {
                encryptedOutput.write(outputFinal);
            }
            return encryptedOutput.toByteArray();
            
        } catch (Exception e) {
            throw new RuntimeException("Error encrypting document", e);
        }
    }


    @Override
    protected byte[] computeMAC(byte[] dataToProtect, String macAlgorithm, byte[] password) {
        try {
          
            SecretKeySpec keySpec = new SecretKeySpec(password, macAlgorithm);
            Mac mac = Mac.getInstance(macAlgorithm);
            mac.init(keySpec);

            return mac.doFinal(dataToProtect);
        } catch (Exception e) {
            throw new RuntimeException("Error computing MAC", e);
        }
    }


    @Override
    protected byte[] computeSignature(byte[] dataToProtect, String signatureAlgorithm, InputStream privateKeySign) {
        try {
            byte[] privateKeyBytes = Helpers.inputStreamToByteArray(privateKeySign); // Use helper method
            if (privateKeyBytes == null) {
                throw new RuntimeException("Failed to convert InputStream to byte array");
            }

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));

            Signature signature = Signature.getInstance(signatureAlgorithm);
            signature.initSign(privateKey);
            signature.update(dataToProtect);

            return signature.sign();
        } catch (Exception e) {
            throw new RuntimeException("Error computing signature", e);
        }
    }

}
