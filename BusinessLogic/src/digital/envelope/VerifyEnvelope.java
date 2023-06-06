package digital.envelope;

import digital.signature.DataSet;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.util.Scanner;

public class VerifyEnvelope {
    public static void main(String[] args) {

        Scanner sc = new Scanner(System.in);
        System.out.print("받을 파일 이름 : "); // .bin
        String sendFName = sc.nextLine();

        System.out.print("전자봉투 검증에 사용할 개인키 파일 : "); // 개인키
        String recPrivateFName = sc.nextLine();
        PrivateKey recPrivateKey;
        try (FileInputStream fis = new FileInputStream(recPrivateFName)) {
            try (ObjectInputStream ois = new ObjectInputStream(fis)) {
                Object obj = ois.readObject();
                recPrivateKey = (PrivateKey) obj;
            }
        } catch (IOException | ClassNotFoundException e) {
            throw new RuntimeException(e);
        }


        try {
            // 1. 받은 파일 읽기
            Path path = (new File(sendFName)).toPath();
            byte[] recBytes = Files.readAllBytes(path);

            SendDataSet recDataSet = null;
            try (ByteArrayInputStream bais = new ByteArrayInputStream(recBytes);
                 ObjectInputStream ois = new ObjectInputStream(bais)) {

                Object obj =  ois.readObject();
                recDataSet = (SendDataSet) obj; // 받은 파일 속 객체

            } catch (IOException e) {
                e.printStackTrace();
            } catch (ClassNotFoundException e) {
                throw new RuntimeException(e);
            }


            // 2. 받은 파일 속 전자봉투, 대칭키로 암호화한 결과 분리
            byte[] envelope = recDataSet.getEnvelope(); // 전자봉투
            byte[] encrypt = recDataSet.getEncryptSet(); // 대칭키로 암호화한 결과


            // 3. 전자봉투 -> 대칭키 획득
            Cipher c2 = Cipher.getInstance("RSA");
            c2.init(Cipher.DECRYPT_MODE, recPrivateKey);
            byte[] decrypt = c2.doFinal(envelope);
            System.out.println("키의 길이 (bytes): " + decrypt.length);

            SecretKey secretKey = new SecretKeySpec(decrypt, "AES"); // 대칭키 획득


            // 4. 대칭키로 암호화한 결과 -> 대칭키로 복호화 -> 원문, 원문 해시값의 암호문, 보낸 이의 공개키 획득
            Cipher c1 = Cipher.getInstance("AES");
            c1.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] dataSetBytes = c1.doFinal(encrypt);

            DataSet dataSet = null;
            try (ByteArrayInputStream bais = new ByteArrayInputStream(dataSetBytes);
                 ObjectInputStream ois = new ObjectInputStream(bais)) {

                Object obj =  ois.readObject();
                dataSet = (DataSet) obj; // 원문, 원문 해시값의 암호문, 보낸 이의 공개키 객체

            } catch (IOException e) {
                e.printStackTrace();
            } catch (ClassNotFoundException e) {
                throw new RuntimeException(e);
            }

            String originFName = dataSet.getOriginFName(); // 원문 텍스트 파일
            byte[] signature = dataSet.getSignature(); // 전자서명
            String pubFName = dataSet.getPubFName(); // 공개키 저장 파일


            // 5. 검증
            byte[] originTxt;
            try (FileInputStream fis = new FileInputStream(originFName)) {
                originTxt = fis.readAllBytes();
            } catch (FileNotFoundException e) {
                throw new RuntimeException(e);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }

            PublicKey senderPublicKey;
            try (FileInputStream fileInputStream = new FileInputStream(pubFName)) {
                try (ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream)) {
                    Object obj = objectInputStream.readObject();
                    senderPublicKey = (PublicKey) obj;
                }
            } catch (IOException | ClassNotFoundException e) {
                throw new RuntimeException(e);
            }


            String signAlgorithm = "SHA256withRSA";
            Signature sig = Signature.getInstance(signAlgorithm);
            sig.initVerify(senderPublicKey);

            MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
            messageDigest.update(originTxt);
            byte[] originHash = messageDigest.digest();
            sig.update(originHash);

            boolean rslt = sig.verify(signature);

            System.out.println("서명 검증 결과 : " + rslt);


        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        }

    }
}
