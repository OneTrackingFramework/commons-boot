/**
 *
 */
package one.tracking.framework.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.filter.CommonsRequestLoggingFilter;

/**
 * @author Marko Voß
 *
 */
@Configuration
public class LoggingFilterConfig {

  @Value("${app.logging.request.include.querystring:true}")
  private boolean includeQueryString;

  @Value("${app.logging.request.include.clientinfo:false}")
  private boolean includeClientInfo;

  @Value("${app.logging.request.include.headers:false}")
  private boolean includeHeaders;

  @Value("${app.logging.request.include.payload:false}")
  private boolean includePayload;

  @Value("${app.logging.request.include.payload.length:10000}")
  private int maxPayloadLength;

  @Bean
  public CommonsRequestLoggingFilter logFilter() {
    final CommonsRequestLoggingFilter filter = new CommonsRequestLoggingFilter();
    filter.setIncludeQueryString(this.includeQueryString);
    filter.setIncludeClientInfo(this.includeClientInfo);
    filter.setIncludeHeaders(this.includeHeaders);
    filter.setIncludePayload(this.includePayload);
    filter.setMaxPayloadLength(this.maxPayloadLength);
    return filter;
  }
}
