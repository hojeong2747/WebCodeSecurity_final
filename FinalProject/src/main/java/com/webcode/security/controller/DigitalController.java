package com.webcode.security.controller;

import com.webcode.security.form.CreateEnvelopeForm;
import com.webcode.security.form.VerifyEnvelopeForm;
import com.webcode.security.service.DigitalService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import javax.validation.Valid;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;

@Controller
@RequiredArgsConstructor
@Slf4j
public class DigitalController {

    private final DigitalService digitalService;

    // 전자봉투 생성
    @GetMapping(value = "/envelope/create")
    public String createEnvelopeForm(Model model) {
        log.info("digital controller");

        model.addAttribute("createEnvelopeForm", new CreateEnvelopeForm());

        return "digital/createEnvelope";
    }

    @PostMapping(value = "/envelope/create")
    public String createEnvelope(@Valid CreateEnvelopeForm form, BindingResult result, RedirectAttributes redirectAttrs) throws NoSuchAlgorithmException, ClassNotFoundException {

        log.info("digital controller");

        if (result.hasErrors()) {
            return "digital/createEnvelope";
        }

        digitalService.saveEnvelope(form);

        // alert
        redirectAttrs.addFlashAttribute("alert", "Digital Envelope creation successful!");

        return "redirect:/";
    }

    // 전자봉투 검증
    @GetMapping(value = "/envelope/verify")
    public String verifyEnvelopeForm(Model model) {
        log.info("digital controller");

        model.addAttribute("verifyEnvelopeForm", new VerifyEnvelopeForm());

        return "digital/verifyEnvelope";
    }

    @PostMapping(value = "/envelope/verify")
    public String verifyEnvelope(@Valid VerifyEnvelopeForm form, BindingResult result, RedirectAttributes redirectAttrs) throws NoSuchAlgorithmException, IOException, ClassNotFoundException {
        log.info("digital controller");

        if (result.hasErrors()) {
            return "digital/verifyEnvelope";
        }

        boolean rslt = digitalService.verifyEnvelope(form);

        // alert
        if (rslt == true) {
            redirectAttrs.addFlashAttribute("alert", "Digital Envelope verification successful!");
        } else {
            redirectAttrs.addFlashAttribute("alert", "Digital Envelope verification failure!");
        }

        return "redirect:/";
    }


}
