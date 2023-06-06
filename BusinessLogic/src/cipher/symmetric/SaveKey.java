package cipher.symmetric;

import javax.crypto.KeyGenerator;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

public class SaveKey {
    public static void main(String[] args) throws NoSuchAlgorithmException {

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
        Scanner sc = new Scanner(System.in);
        System.out.print("대칭키(비밀키)를 저장할 파일 이름: ");
        String fName = sc.nextLine();

        try (FileOutputStream fos = new FileOutputStream(fName)) {
            try (ObjectOutputStream oos = new ObjectOutputStream(fos)) {
                oos.writeObject(secretKey);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
