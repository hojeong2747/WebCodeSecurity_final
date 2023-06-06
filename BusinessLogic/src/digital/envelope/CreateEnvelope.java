package digital.envelope;

import digital.signature.DataSet;

import javax.crypto.*;
import java.io.*;
import java.security.*;
import java.util.Scanner;

public class CreateEnvelope {
    public static void main(String[] args) throws FileNotFoundException {

        // 1. 원문 파일 생성
        Scanner sc = new Scanner(System.in);
        System.out.print("원문 파일 이름 : "); // .txt
        String originFName = sc.nextLine();

        FileOutputStream fos = null;
        BufferedReader br = null;
        try {

            fos = new FileOutputStream(originFName);
            System.out.print("원문 파일에 들어갈 내용 : ");
            br = new BufferedReader(new InputStreamReader(System.in));

            byte[] originTxt;
            originTxt = br.readLine().getBytes();
            fos.write(originTxt); // BufferedReader 로 읽어서 byte 로 변환 후 fos 로 파일에 작성


            // 2. 전자서명 생성 (원문 파일 내용에 대한 해시값 생성 -> A 개인키로 암호화)
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
            messageDigest.update(originTxt);
            byte[] originHash = messageDigest.digest(); // 해시값 생성

            System.out.print("암호화에 사용할 개인키 파일 : "); // 개인키
            String senderPrivateFName = sc.nextLine();

            PrivateKey senderPrivateKey;
            try (FileInputStream fis = new FileInputStream(senderPrivateFName)) {
                try (ObjectInputStream ois = new ObjectInputStream(fis)) {

                    Object obj = ois.readObject();
                    senderPrivateKey = (PrivateKey) obj;

                }
            } catch (IOException | ClassNotFoundException e) {
                throw new RuntimeException(e);
            }

            String signAlgorithm = "SHA256withRSA";
            Signature sig = Signature.getInstance(signAlgorithm);
            sig.initSign(senderPrivateKey);
            sig.update(originHash);
            byte[] signature = sig.sign(); // 전자서명 생성 (개인키로 해시값 암호화)

            System.out.print("서명을 저장할 파일 이름: ");
            String saveFName = sc.nextLine();
            try (FileOutputStream fileOutputStream = new FileOutputStream(saveFName)) {
                try (ObjectOutputStream objectOutputStream = new ObjectOutputStream(fileOutputStream)) {
                    objectOutputStream.writeObject(signature);
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }

            System.out.println("서명을 파일에 저장했습니다."); // 전자서명 파일에 저장

            System.out.print("전송할 공개키 파일 : "); // 공개키
            String senderPublicFName = sc.nextLine();


            // 3. 원문 파일, 전자서명, A 공개키를 하나의 객체에 담고 직렬화
            DataSet dataSet = new DataSet(originFName, signature, senderPublicFName);

            // dataSet 직렬화 -> byte[]
            byte[] dataSetBytes;
            dataSetBytes = new byte[0];
            try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
                 ObjectOutputStream oos = new ObjectOutputStream(baos)){

                oos.writeObject(dataSet);
                dataSetBytes = baos.toByteArray();

            } catch (IOException e) {
                e.printStackTrace();
            }


            // 4. 전자봉투 생성 (대칭키로 dataSetBytes 암호화 & 대칭키를 B 공개키로 암호화)
            System.out.print("대칭키(비밀키) 파일 이름: "); // 대칭키
            String secretFName = sc.nextLine();
            Key secretKey;
            try (FileInputStream fileInputStream = new FileInputStream(secretFName)) {
                try (ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream)) {
                    Object obj = objectInputStream.readObject();
                    secretKey = (Key) obj;
                }
            } catch (IOException | ClassNotFoundException e) {
                throw new RuntimeException(e);
            }

            Cipher c1 = Cipher.getInstance("AES");
            c1.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptSet = c1.doFinal(dataSetBytes); // 대칭키로 dataSetBytes 암호화

            System.out.print("받는 사람의 공개키 파일 : "); // 공개키
            String recPrivateFName = sc.nextLine();
            PublicKey recPublicKey;
            try (FileInputStream fis = new FileInputStream(recPrivateFName)) {
                try (ObjectInputStream ois = new ObjectInputStream(fis)) {
                    Object obj = ois.readObject();
                    recPublicKey = (PublicKey) obj;
                }
            } catch (IOException | ClassNotFoundException e) {
                throw new RuntimeException(e);
            }

            Cipher c2 = Cipher.getInstance("RSA");
            c2.init(Cipher.ENCRYPT_MODE, recPublicKey);
            byte[] envelope = c2.doFinal(secretKey.getEncoded()); // 대칭키를 B 공개키로 암호화 = 전자봉투


            // 5. 대칭키로 암호화한 결과, 전자봉투 한 객체에 담고 직렬화해서 보낼 파일 하나 생성
            SendDataSet sendDataSet = new SendDataSet(encryptSet, envelope);

            byte[] sendBytes;
            sendBytes = new byte[0];
            try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
                 ObjectOutputStream oos = new ObjectOutputStream(baos)){

                oos.writeObject(sendDataSet);
                sendBytes = baos.toByteArray();

            } catch (IOException e) {
                e.printStackTrace();
            }

            System.out.print("보낼 파일 이름 : "); // .bin
            String sendFName = sc.nextLine();

            fos = new FileOutputStream(sendFName);
            fos.write(sendBytes);

            System.out.println("보낼 파일이 저장되었습니다.");


        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        }

    }
}
