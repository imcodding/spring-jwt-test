package spring.security.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.io.UnsupportedEncodingException;
import java.sql.Date;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@Component
public class JwtTokenProvider {

    @Value("${JWT.SECRET}")
    private String secretKey;
    @Value("${JWT.ISSUER}")
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
                    .withHeader(creatJwtHeader()) //헤더타입 설정(JWT)
                    .withIssuer(issuer) //발급자
                    .withIssuedAt(Date.from(now.toInstant())) //발급시간
                    .withExpiresAt(Date.from(now.toInstant().plusSeconds(tokenValidTime))) //만료시간
                    .withClaim("email", String.valueOf(email))
                    .sign(Algorithm.HMAC256(secretKey));
        } catch (JWTCreationException | UnsupportedEncodingException e) {
            return "토큰 생성 실패";
        }
    }

    private Map<String, Object> creatJwtHeader() {
        Map<String, Object> headers = new HashMap<>();
        headers.put("typ", "JWT");
        return headers;
    }
}
