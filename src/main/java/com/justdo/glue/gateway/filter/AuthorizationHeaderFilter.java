package com.justdo.glue.gateway.filter;

import com.justdo.glue.gateway.utils.JwtTokenProvider;
import java.util.Objects;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class AuthorizationHeaderFilter extends
        AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    public AuthorizationHeaderFilter() {
        super(Config.class);
    }

    public static class Config {

    }

    @Override
    public GatewayFilter apply(Config config) {
        return ((exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();

            String requestUrl = exchange.getRequest().getPath().toString();

            if (requestUrl.startsWith("/auths/v3/api-docs") ||
                    requestUrl.startsWith("/blogs/v3/api-docs") ||
                    requestUrl.startsWith("/posts/v3/api-docs") ||
                    requestUrl.startsWith("/stickers/v3/api-docs") ||
                    requestUrl.startsWith("/recommends/openapi.json") ||
                    requestUrl.startsWith("/auths/login")) {
                return chain.filter(exchange);
            }

            if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                return onError(exchange, "no authorization header");
            }

            String authorizationHeader = Objects.requireNonNull(
                    request.getHeaders().get(HttpHeaders.AUTHORIZATION)).get(0);
            String jwt = authorizationHeader.replace("Bearer", "").trim();

            if (!jwtTokenProvider.isTokenValid(jwt)) {
                return onError(exchange, "JWT Token is not valid");
            }

            return chain.filter(exchange);
        });
    }

    private Mono<Void> onError(ServerWebExchange exchange, String err) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);

        return response.setComplete();
    }
}