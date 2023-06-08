package com.webcode.security.service;

import com.webcode.security.form.AsymmetricForm;
import com.webcode.security.form.SymmetricForm;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.crypto.KeyGenerator;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;

@Service
@RequiredArgsConstructor
public class KeyService {

    private static int RSA_KEY_SIZE = 1024;
    public static final int getRsaKeySize() {
        return RSA_KEY_SIZE;
    }
    private static int AES_KEY_SIZE = 128;
    public static final int getAesKeySize() {
        return AES_KEY_SIZE;
    }

    private static final Logger LOGGER = LoggerFactory.getLogger(KeyService.class);

    // 비대칭키 생성, 저장
    public void saveAsymmetricKey(AsymmetricForm form) throws NoSuchAlgorithmException {
        String publicFName = form.getPublicFName();
        String privateFName = form.getPrivateFName();

        // 1. KeyPair 생성
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(getRsaKeySize());
        KeyPair kp = kpg.generateKeyPair();

        PublicKey publicKey = kp.getPublic();
        PrivateKey privateKey = kp.getPrivate();

        // 2. byte[]로 가져와서 길이 확인 후 몇 개 찍어보기 (출력 확인)
        byte[] publicKeyBytes = publicKey.getEncoded();
        byte[] privateKeyBytes = privateKey.getEncoded();

        LOGGER.info("공개키의 길이 (bytes): {}", publicKeyBytes.length);
        StringBuilder hexString2 = new StringBuilder();
        for (byte bytes : publicKeyBytes) {
            hexString2.append(String.format("%02x", bytes)).append("\t");
        }
        LOGGER.info(hexString2.toString());

        LOGGER.info("개인키의 길이 (bytes): {}", privateKeyBytes.length);
        StringBuilder hexString = new StringBuilder();
        for (byte bytes : privateKeyBytes) {
            hexString.append(String.format("%02x", bytes)).append("\t");
        }
        LOGGER.info(hexString.toString());


        // 3. KeyPair 파일에 저장
        saveKeyToFile(publicKey, publicFName);
        saveKeyToFile(privateKey, privateFName);

    }

    // 대칭키 생성, 저장
    public void saveSymmetricKey(SymmetricForm form) throws NoSuchAlgorithmException {

        String fName = form.getSecretFName();

        // 1. key 생성
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(getAesKeySize());
        Key secretKey = kg.generateKey();

        // 2. byte[]로 가져와서 길이 확인 후 몇 개 찍어보기 (출력 확인)
        byte[] secretKeyBytes = secretKey.getEncoded();

        LOGGER.info("대칭키(비밀키)의 길이 (bytes): {}", secretKeyBytes.length);
        StringBuilder hexString = new StringBuilder();
        for (byte bytes : secretKeyBytes) {
            hexString.append(String.format("%02x", bytes)).append("\t");
        }
        LOGGER.info(hexString.toString());

        // 3. Key 파일에 저장
        saveKeyToFile(secretKey, fName);
    }

    private void saveKeyToFile(Serializable key, String fName) {
        if (Files.exists(Paths.get(fName))) {
            throw new IllegalStateException("File already exists: " + fName);
        }

        try (FileOutputStream fos = new FileOutputStream(fName);
             ObjectOutputStream oos = new ObjectOutputStream(fos)) {
            oos.writeObject(key);
        } catch (IOException e) {
            LOGGER.error("Failed to write key to file", e);
            throw new IllegalStateException("Failed to write key to file", e);
        }
    }

}
