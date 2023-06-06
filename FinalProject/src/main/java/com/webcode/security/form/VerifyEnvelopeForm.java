package com.webcode.security.form;

import lombok.Getter;
import lombok.Setter;

import javax.validation.constraints.NotEmpty;

@Getter
@Setter
public class VerifyEnvelopeForm {

    @NotEmpty(message = "파일 이름은 필수입니다.")
    private String sendFName; // 받을 파일 이름

    @NotEmpty(message = "파일 이름은 필수입니다.")
    private String recPrivateFName; // 전자봉투 검증에 사용할 개인키 파일 이름
}
