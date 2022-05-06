package be.jevent.gatewayservice.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
public class GateWayController {

    private static final Logger LOGGER = LoggerFactory.getLogger(GateWayController.class);
    private final static String EMAIL_CLAIM = "https://example.com/email";
    private final static String SCOPE_CLAIM = "https://example.com/roles";

    @GetMapping(value = "/token")
    public Mono<String> getHome(@AuthenticationPrincipal Jwt principal){
        return Mono.just(principal.getClaims().toString());
    }

    @GetMapping("/whoami")
    public String index(@AuthenticationPrincipal Jwt principal) {
        return "email " +  principal.getClaims().get("preferred_username") + " " + principal.getClaims().get("scope").toString();
    }
}
