package com.webcode.security.service;

import com.webcode.security.form.CreateEnvelopeForm;
import com.webcode.security.controller.data.DataSet;
import com.webcode.security.controller.data.SendDataSet;
import com.webcode.security.form.VerifyEnvelopeForm;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;

@Service
@RequiredArgsConstructor
public class DigitalService {

    // 전자봉투 생성
    public void saveEnvelope(CreateEnvelopeForm form) {
        String originFName = form.getOriginFName(); // 원문 파일 이름
        String originString = form.getOriginString(); // 원문 파일 내용
        String senderPrivateFName = form.getSenderPrivateFName(); // 암호화에 사용할 개인키 파일 이름
        String saveFName = form.getSaveFName(); // 서명을 저장할 파일 이름
        String senderPublicFName = form.getSenderPublicFName(); // 전송할 공개키 파일 이름
        String secretFName = form.getSecretFName(); // 대칭키 파일 이름
        String recPrivateFName = form.getRecPrivateFName(); // 받는 사람의 공개키 파일
        String sendFName = form.getSendFName(); // 보낼 파일 이름


        // 1. 원문 파일 생성
        FileOutputStream fos = null;
        try {

            fos = new FileOutputStream(originFName);

            byte[] originTxt;
            originTxt = originString.getBytes();
            fos.write(originTxt); // byte 로 변환 후 fos 로 파일에 작성

            // 2. 전자서명 생성 (원문 파일 내용에 대한 해시값 생성 -> A 개인키로 암호화)
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
            messageDigest.update(originTxt);
            byte[] originHash = messageDigest.digest(); // 해시값 생성

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

            try (FileOutputStream fileOutputStream = new FileOutputStream(saveFName)) {
                try (ObjectOutputStream objectOutputStream = new ObjectOutputStream(fileOutputStream)) {
                    objectOutputStream.writeObject(signature);
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }

            System.out.println("서명을 파일에 저장했습니다."); // 전자서명 파일에 저장

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

    public boolean verifyEnvelope(VerifyEnvelopeForm form) {
        String sendFName = form.getSendFName();
        String recPrivateFName = form.getRecPrivateFName();

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

            return rslt;

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
