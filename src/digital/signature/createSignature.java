package digital.signature;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.*;
import java.util.Scanner;

public class createSignature {
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, SignatureException {

        Scanner sc = new Scanner(System.in);
        System.out.print("원문 파일 이름 : ");
        String originFName = sc.nextLine();

        byte[] originTxt;
        try (FileInputStream fis = new FileInputStream(originFName)) {

            // 1. 원문 파일 (plain.txt) byte 배열로 읽기
            originTxt = fis.readAllBytes();

        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        // 2. 원문 파일 (plain.txt) 에 대한 해시값 생성
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
        messageDigest.update(originTxt);
        byte[] originHash = messageDigest.digest();

        System.out.println("계산된 해시값 : "); // 출력 확인
        for (byte bytes : originHash) {
            System.out.print(String.format("%02x", bytes) + "\t");
        }
        System.out.println();

        // 3. 해시값 파일에 저장
        System.out.print("해시값 저장할 파일 이름 : ");
        String hashFName = sc.nextLine();

        try (PrintWriter out = new PrintWriter(new FileWriter(hashFName))) {

            for (byte bytes : originHash) {
                out.print(String.format("%02x", bytes) + "\t");
            }
            out.println();

        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        // 4. 철수의 개인키로 암호화 (-> 전자서명)
        System.out.print("암호화에 사용할 개인키 파일 : ");
        String privateFName = sc.nextLine();

        PrivateKey privateKey;
        try (FileInputStream fis = new FileInputStream(privateFName)) {
            try (ObjectInputStream ois = new ObjectInputStream(fis)) {

                Object obj = ois.readObject();
                privateKey = (PrivateKey) obj;

            }
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException | ClassNotFoundException e) {
            throw new RuntimeException(e);
        }

        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(privateKey);
        sig.update(originHash);
        byte[] signature = sig.sign(); // 전자서명 생성

        System.out.println("생성된 서명 정보: " + signature.length + " bytes");
        for (byte bytes : signature) {
            System.out.print(String.format("%02x", bytes) + "\t");
        }
        System.out.println("\n");


        // 5. 전자서명 파일에 저장
        System.out.print("서명을 저장할 파일 이름: ");
        String saveFName = sc.nextLine();
        try (FileOutputStream fileOutputStream = new FileOutputStream(saveFName)) {
            try (ObjectOutputStream objectOutputStream = new ObjectOutputStream(fileOutputStream)) {
                objectOutputStream.writeObject(signature);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        System.out.println("서명을 파일에 저장했습니다.");

    }
}
