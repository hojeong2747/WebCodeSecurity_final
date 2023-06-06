package com.webcode.security.form;

import lombok.Getter;
import lombok.Setter;

import javax.validation.constraints.NotEmpty;

@Getter
@Setter
public class AsymmetricForm {

    @NotEmpty(message = "파일 이름은 필수입니다.")
    private String publicFName;

    @NotEmpty(message = "파일 이름은 필수입니다.")
    private String privateFName;
}
