package spring.security.login;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import spring.security.jwt.JwtTokenProvider;

import java.util.Map;

@RestController
@RequiredArgsConstructor
public class LoginController {

    private final JwtTokenProvider jwtTokenProvider;
    @PostMapping("/login")
    public String login(@RequestBody Map<String, String> map) {

        return jwtTokenProvider.createToken(map.get("email"));
    }
}
