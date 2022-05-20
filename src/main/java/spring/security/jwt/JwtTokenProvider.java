package spring.security.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.sql.Date;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@Component
public class JwtTokenProvider {

    private String secretKey = "HELLO_KEY";
    private String issuer;

    //토큰 유효시간 30분
    private final static long tokenValidTime = 30 * 60;

    @PostConstruct
    protected void init() {
        secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
    }

    //jwt 생성
    public String createToken(String email) {
        try {
            final ZonedDateTime now = ZonedDateTime.now();
            return JWT.create()
                    .withHeader(creatJwtHeader())
                    .withIssuer(issuer)
                    .withClaim("email", String.valueOf(email))
                    .withIssuedAt(Date.from(now.toInstant()))
                    .withExpiresAt(Date.from(now.toInstant().plusSeconds(tokenValidTime)))
                    .sign(Algorithm.HMAC512(secretKey));
        } catch (Exception e) {
            return "토큰 생성 실패";
        }
    }

    private Map<String, Object> creatJwtHeader() {
        Map<String, Object> headers = new HashMap<>();
        headers.put("typ", "JWT");
        return headers;
    }
}
