package digital.signature;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Scanner;

public class VerifySignature {
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, ClassNotFoundException, IOException {

        Scanner sc = new Scanner(System.in);
        System.out.print("원문 파일 이름 : ");
        String originFName = sc.nextLine();

        byte[] originHash;
        try (FileInputStream fis = new FileInputStream(originFName)) {

            // 1. 원문 파일 (plain.txt) byte 배열로 읽기
            originHash = fis.readAllBytes();

        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        // 2. 철수의 공개키 파일 읽기
        System.out.print("전자서명 검증에 사용할 공개키 파일 : ");
        String publicFName = sc.nextLine();

        PublicKey publicKey;
        try (FileInputStream fileInputStream = new FileInputStream(publicFName)) {
            try (ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream)) {

                Object obj = objectInputStream.readObject();
                publicKey = (PublicKey) obj;

            }
        } catch (IOException | ClassNotFoundException e) {
            throw new RuntimeException(e);
        }

        // 3. 전자서명 결과 파일 읽기
        System.out.print("전자서명 파일 이름: ");
        String signFName = sc.nextLine();
        byte[] signature;
        try (FileInputStream fileInputStream = new FileInputStream(signFName)) {
            try (ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream)) {

                Object obj = objectInputStream.readObject();
                signature = (byte[]) obj;

            }
        } catch (IOException | ClassNotFoundException e) {
            throw new RuntimeException(e);
        }

        System.out.println("입력된 서명 정보: " + signature.length + " bytes");
        for (byte bytes : signature) {
            System.out.print(String.format("%02x", bytes) + "\t");
        }
        System.out.println("\n");

        // 4. 검증
        String signAlgorithm = "SHA256withRSA";
        Signature sig = Signature.getInstance(signAlgorithm);
        sig.initVerify(publicKey);
        sig.update(originHash);

        boolean rslt = sig.verify(signature);

        System.out.println("서명 검증 결과 : " + rslt);

    }
}
