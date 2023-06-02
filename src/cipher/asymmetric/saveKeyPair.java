package cipher.asymmetric;

import java.awt.*;
import java.io.*;
import java.security.*;
import java.util.Scanner;

public class saveKeyPair {
    public static void main(String[] args) throws NoSuchAlgorithmException {

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
        Scanner sc = new Scanner(System.in);
        System.out.print("공개키를 저장할 파일 이름 : ");
        String publicFName = sc.nextLine();

        try (FileOutputStream fos = new FileOutputStream(publicFName)) {
            try (ObjectOutputStream oos = new ObjectOutputStream(fos)) {
                oos.writeObject(publicKey);
            }
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        System.out.print("개인키를 저장할 파일 이름 : ");
        String privateFName = sc.nextLine();

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
}
