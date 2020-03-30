/**
 *
 */
package one.tracking.framework.util;

import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import one.tracking.framework.security.SecurityConstants;

/**
 * @author Marko Voß
 *
 */
@Component
public class JWTHelper {

  @Value("${app.token.secret}")
  private String tokenSecret;

  public String createJWT(final String subject, final long expiration, final String... roles) {

    final Claims claims = Jwts.claims().setSubject(subject);

    if (roles != null && roles.length > 0)
      claims.put(SecurityConstants.AUTHZ_ROLES, Arrays.asList(roles));

    return Jwts.builder().setSubject(subject)
        .setExpiration(Date.from(Instant.now().plusSeconds(expiration)))
        .setIssuedAt(Date.from(Instant.now()))
        .setIssuer(SecurityConstants.ISSUER)
        .signWith(SignatureAlgorithm.HS512, this.tokenSecret)
        .setClaims(claims)
        .compact();
  }

  public Claims decodeJWT(final String token) {

    return Jwts.parser()
        .setSigningKey(this.tokenSecret)
        .parseClaimsJws(token)
        .getBody();
  }
}
