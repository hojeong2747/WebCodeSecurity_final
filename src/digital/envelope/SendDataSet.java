package digital.envelope;

import java.io.Serializable;

public class SendDataSet implements Serializable {

    private static final long serialVersionUID = 1L;

    byte[] encryptSet; // 대칭키로 암호화한 DataSet
    byte[] envelope; // 전자봉투 (대칭키를 받는 이의 공개키로 암호화)

    public SendDataSet() {
    }

    public SendDataSet(byte[] encryptSet, byte[] envelope) {
        this.encryptSet = encryptSet;
        this.envelope = envelope;
    }

    // getter, setter 필요하면 추가

    public byte[] getEncryptSet() {
        return encryptSet;
    }

    public byte[] getEnvelope() {
        return envelope;
    }
}
