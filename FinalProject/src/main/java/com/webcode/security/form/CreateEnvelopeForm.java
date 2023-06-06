package com.webcode.security.form;

import lombok.Getter;
import lombok.Setter;

import javax.validation.constraints.NotEmpty;

@Getter
@Setter
public class CreateEnvelopeForm {

    @NotEmpty(message = "파일 이름은 필수입니다.")
    private String originFName; // 원문 파일 이름 .txt

    @NotEmpty(message = "파일 내용은 필수입니다.")
    private String originString; // 원문 파일 내용

    @NotEmpty(message = "파일 이름은 필수입니다.")
    private String senderPrivateFName; // 암호화에 사용할 개인키 파일 이름

    @NotEmpty(message = "파일 이름은 필수입니다.")
    private String saveFName; // 서명을 저장할 파일 이름

    @NotEmpty(message = "파일 이름은 필수입니다.")
    private String senderPublicFName; // 전송할 공개키 파일 이름

    @NotEmpty(message = "파일 이름은 필수입니다.")
    private String secretFName; // 대칭키 파일 이름

    @NotEmpty(message = "파일 이름은 필수입니다.")
    private String recPrivateFName; // 받는 사람의 공개키 파일

    @NotEmpty(message = "파일 이름은 필수입니다.")
    private String sendFName; // 보낼 파일 이름
}
