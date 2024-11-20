

Encrypt:
1. java ch.zhaw.securitylab.slcrypt.encrypt.SLEncrypt data/brunndar_sigritim_05.txt data/aes_cbc.enc data/encryptCert.crt AES/CBC/PKCS5Padding 192 M HmacSHA256 supersecret
2. java ch.zhaw.securitylab.slcrypt.encrypt.SLEncrypt data/brunndar_sigritim_05.txt data/aes_gcm.enc data/encryptCert.crt AES/GCM/NoPadding 256 M HmacSHA3-256 supersecret
3. java -cp bcprov-jdk18on-1.79.jar:. ch.zhaw.securitylab.slcrypt.encrypt.SLEncrypt data/brunndar_sigritim_05.txt data/seed_ctr.enc data/encryptCert.crt SEED/CTR/NoPadding 128 S SHA256withRSA data/signKey.key data/signCert.crt
4. java ch.zhaw.securitylab.slcrypt.encrypt.SLEncrypt data/brunndar_sigritim_05.txt data/rc4.enc data/encryptCert.crt RC4 128 S SHA3-256withRSA data/signKey.key data/signCert.crt
5. java ch.zhaw.securitylab.slcrypt.encrypt.SLEncrypt data/brunndar_sigritim_05.txt data/chacha20.enc data/encryptCert.crt CHACHA20 256 N 

Decrypt:
1. java ch.zhaw.securitylab.slcrypt.decrypt.SLDecrypt data/aes_cbc.enc data/aes_cbc.dec data/encryptKey.key supersecret
2. java ch.zhaw.securitylab.slcrypt.decrypt.SLDecrypt data/aes_gcm.enc data/aes_gcm.dec data/encryptKey.key supersecret
3. java -cp bcprov-jdk18on-1.79.jar:. ch.zhaw.securitylab.slcrypt.decrypt.SLDecrypt data/seed_ctr.enc data/seed_ctr.dec data/encryptKey.key supersecret
4. java ch.zhaw.securitylab.slcrypt.decrypt.SLDecrypt data/rc4.enc data/rc4.dec data/encryptKey.key supersecret
5. java ch.zhaw.securitylab.slcrypt.decrypt.SLDecrypt data/chacha20.enc data/chacha20.dec data/encryptKey.key supersecret
