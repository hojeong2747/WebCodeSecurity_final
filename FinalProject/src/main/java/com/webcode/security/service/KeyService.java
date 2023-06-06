package com.webcode.security.service;

import com.webcode.security.form.AsymmetricForm;
import com.webcode.security.form.SymmetricForm;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import javax.crypto.KeyGenerator;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.*;

@Service
@RequiredArgsConstructor
public class KeyService {

    // 비대칭키 생성, 저장
    public void saveAsymmetricKey(AsymmetricForm form) throws NoSuchAlgorithmException {
        String publicFName = form.getPublicFName();
        String privateFName = form.getPrivateFName();

        // 1. KeyPair 생성
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024);
        KeyPair kp = kpg.generateKeyPair();

        PublicKey publicKey = kp.getPublic();
        PrivateKey privateKey = kp.getPrivate();

        // 2. byte[]로 가져와서 길이 확인 후 몇 개 찍어보기 (출력 확인)
        byte[] publicKeyBytes = publicKey.getEncoded();
        byte[] privateKeyBytes = privateKey.getEncoded();
        System.out.println("생성된 공개키 정보: ");
        System.out.println("키의 길이 (bytes): " + publicKeyBytes.length);
        for (byte bytes : publicKeyBytes) {
            System.out.print(String.format("%02x", bytes) + "\t");
        }

        System.out.println("\n생성된 개인키 정보: ");
        System.out.println("키의 길이 (bytes): " + privateKeyBytes.length);
        for (byte bytes : privateKeyBytes) {
            System.out.print(String.format("%02x", bytes) + "\t");
        }
        System.out.println("\n");

        // 3. KeyPair 파일에 저장
        try (FileOutputStream fos = new FileOutputStream(publicFName)) {
            try (ObjectOutputStream oos = new ObjectOutputStream(fos)) {
                oos.writeObject(publicKey);
            }
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        try (FileOutputStream fos = new FileOutputStream(privateFName)) {
            try (ObjectOutputStream oos = new ObjectOutputStream(fos)) {
                oos.writeObject(privateKey);
            }
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }


    }

    // 대칭키 생성, 저장
    public void saveSymmetricKey(SymmetricForm form) throws NoSuchAlgorithmException {

        String fName = form.getSecretFName();

        // 1. key 생성
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128);
        Key secretKey = kg.generateKey();

        // 2. byte[]로 가져와서 길이 확인 후 몇 개 찍어보기 (출력 확인)
        byte[] secretKeyBytes = secretKey.getEncoded();
        System.out.println("키의 길이 (bytes): " + secretKeyBytes.length);

        for (byte bytes : secretKeyBytes) {
            System.out.print(String.format("%02x", bytes) + "\t");
        }
        System.out.println();

        // 3. Key 파일에 저장
        try (FileOutputStream fos = new FileOutputStream(fName)) {
            try (ObjectOutputStream oos = new ObjectOutputStream(fos)) {
                oos.writeObject(secretKey);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
