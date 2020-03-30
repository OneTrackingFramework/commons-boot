package one.tracking.framework.security;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import io.jsonwebtoken.Claims;
import one.tracking.framework.util.JWTHelper;

public abstract class BearerAuthenticationFilter extends BasicAuthenticationFilter {

  private final JWTHelper jwtHelper;

  public BearerAuthenticationFilter(final AuthenticationManager authManager, final JWTHelper jwtHelper) {
    super(authManager);
    this.jwtHelper = jwtHelper;
  }

  @Override
  protected void doFilterInternal(final HttpServletRequest req, final HttpServletResponse res, final FilterChain chain)
      throws IOException, ServletException {

    final String header = req.getHeader(HttpHeaders.AUTHORIZATION);

    if (header == null || !header.startsWith(SecurityConstants.TOKEN_PREFIX)) {
      chain.doFilter(req, res);
      return;
    }

    final UsernamePasswordAuthenticationToken authentication = getAuthentication(header);
    SecurityContextHolder.getContext().setAuthentication(authentication);
    chain.doFilter(req, res);
  }

  /**
   *
   * @param request
   * @return
   */
  private UsernamePasswordAuthenticationToken getAuthentication(final String authHeader) {

    if (authHeader == null)
      return null;

    final String bearerToken = authHeader.replace(SecurityConstants.TOKEN_PREFIX, "");

    final Claims claims = this.jwtHelper.decodeJWT(bearerToken);
    final String userId = claims.getSubject();

    if (userId == null)
      return null;

    if (!checkIfUserExists(userId))
      return null;

    @SuppressWarnings("unchecked")
    final List<String> roles = claims.get("scopes", List.class);
    final List<GrantedAuthority> authorities = roles == null ? Collections.emptyList()
        : roles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());

    return new UsernamePasswordAuthenticationToken(userId, null, authorities);
  }

  protected abstract boolean checkIfUserExists(String userId);

}
