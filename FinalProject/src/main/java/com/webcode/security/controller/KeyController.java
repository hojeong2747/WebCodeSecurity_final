package com.webcode.security.controller;

import com.webcode.security.form.AsymmetricForm;
import com.webcode.security.form.SymmetricForm;
import com.webcode.security.service.KeyService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import javax.validation.Valid;
import java.security.NoSuchAlgorithmException;

@Controller
@RequiredArgsConstructor
@Slf4j
public class KeyController {

    private final KeyService keyService;

    // 비대칭키 생성, 저장
    @GetMapping(value = "/key/asymmetric")
    public String createAsymmetricForm(Model model) {
        log.info("key controller");

        model.addAttribute("asymmetricForm", new AsymmetricForm());

        return "key/createAsymmetric";
    }

    @PostMapping(value = "/key/asymmetric")
    public String createAsymmetric(@Valid AsymmetricForm form, BindingResult result, RedirectAttributes redirectAttrs) throws NoSuchAlgorithmException {
        log.info("key controller");

        if (result.hasErrors()) {
            return "key/createAsymmetric";
        }

        keyService.saveAsymmetricKey(form);

        // alert
        redirectAttrs.addFlashAttribute("alert", "Key creation successful!");

        return "redirect:/";
    }

    // 대칭키 생성, 저장
    @GetMapping(value = "/key/symmetric")
    public String createSymmetricForm(Model model) {
        log.info("key controller");

        model.addAttribute("symmetricForm", new SymmetricForm());

        return "key/createSymmetric";
    }

    @PostMapping(value = "/key/symmetric")
    public String createSymmetric(@Valid SymmetricForm form, BindingResult result, RedirectAttributes redirectAttrs) throws NoSuchAlgorithmException {
        log.info("key controller");

        if (result.hasErrors()) {
            return "key/createSymmetric";
        }

        keyService.saveSymmetricKey(form);

        // alert
        redirectAttrs.addFlashAttribute("alert", "Key creation successful!");

        return "redirect:/";
    }




}
