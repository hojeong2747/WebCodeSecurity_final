package com.webcode.security.controller.data;

import java.io.Serializable;

public class DataSet implements Serializable {

    private static final long serialVersionUID = 1L;

    String originFName; // 원문 텍스트 파일
    byte[] signature; // 전자서명
    String pubFName; // 공개키 저장 파일

    public DataSet() {
    }

    public DataSet(String originFName, byte[] signature, String pubFName) {
        this.originFName = originFName;
        this.signature = signature;
        this.pubFName = pubFName;
    }

    // getter, setter 필요한 경우에 추가


    public String getOriginFName() {
        return originFName;
    }

    public byte[] getSignature() {
        return signature;
    }

    public String getPubFName() {
        return pubFName;
    }
}