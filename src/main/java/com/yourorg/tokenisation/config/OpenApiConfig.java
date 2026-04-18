package com.yourorg.tokenisation.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * SpringDoc / OpenAPI configuration.
 *
 * <p>Exposes interactive API documentation at:
 * <ul>
 *   <li>{@code /swagger-ui.html} — Swagger UI browser interface
 *   <li>{@code /v3/api-docs} — raw OpenAPI 3.0 JSON descriptor
 * </ul>
 *
 * <p>The {@code X-Merchant-ID} header is declared as a global API-key security scheme
 * so that the Swagger UI "Authorize" dialog can pre-populate it for try-out requests.
 */
@Configuration
public class OpenApiConfig {

    /**
     * Produces the OpenAPI descriptor for the card tokenisation API.
     *
     * @return the configured {@link OpenAPI} instance
     */
    @Bean
    public OpenAPI cardTokenisationOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("Card Tokenisation System API")
                        .description("""
                                PCI-DSS aligned card tokenisation vault.

                                Replaces raw PANs with opaque tokens using AES-256-GCM envelope encryption.
                                Supports both deterministic (RECURRING) and non-deterministic (ONE_TIME) tokens.

                                **Detokenisation** requires the `X-Merchant-ID` header.
                                Tokens are merchant-scoped — a token issued for Merchant A cannot be
                                detokenised by Merchant B.
                                """)
                        .version("1.0.0")
                        .license(new License()
                                .name("Internal use only")
                                .url("https://internal")))
                .addServersItem(new Server()
                        .url("/")
                        .description("Current server"))
                .components(new Components()
                        .addSecuritySchemes("merchantId",
                                new SecurityScheme()
                                        .type(SecurityScheme.Type.APIKEY)
                                        .in(SecurityScheme.In.HEADER)
                                        .name("X-Merchant-ID")
                                        .description("Merchant identity header required for detokenisation. "
                                                + "Tokens are scoped per merchant.")));
    }
}
