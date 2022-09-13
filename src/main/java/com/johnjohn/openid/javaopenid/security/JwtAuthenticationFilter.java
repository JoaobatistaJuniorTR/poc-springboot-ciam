package com.johnjohn.openid.javaopenid.security;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import io.jsonwebtoken.*;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUserDetailsService jwtUserDetailsService;

    @SuppressWarnings("rawtypes")
    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse,
            FilterChain filterChain) throws ServletException, IOException {
        String header = httpServletRequest.getHeader("Authorization");
        String ciamID = null;
        String tenant = null;
        // if (header != null && header.startsWith("Bearer ")) {
        //     String token = header.replace("Bearer ", "");
        //     try {

        //         String[] splitToken = token.split("\\.");
        //         Jwt<Header, Claims> claims = Jwts.parser().parseClaimsJwt(splitToken[0] + "." + splitToken[1] + ".");
        //         String scope = (String) claims.getBody().get("scope");

        //         String scopeGateway = "https://api.thomsonreuters.com/auth/onesource.obti.gateway.write";
        //         if (!scopeGateway.equals(scope)) {
        //             throw new IncorrectClaimException(
        //                     claims.getHeader(),
        //                     claims.getBody(),
        //                     "Scope inválido");
        //         }

        //         ciamID = (String) claims.getBody().get("azp");
        //         String finalCiamID = ciamID;
        //         // tenant = masterTenantService.existsByCiamId(ciamID).
        //         // orElseThrow(() -> {
        //         // log.error("Ciam Id Inexistente: " + finalCiamID);
        //         // return new BadCredentialsException("Ciam Id Inexistente");

        //         // }).getTenant();

        //         // DBContextHolder.setCurrentTenant(tenant);

        //     } catch (IllegalArgumentException ex) {
        //         throw new BadCredentialsException("Token Inválido.");
        //     }
        // }
        // if (ciamID != null && SecurityContextHolder.getContext().getAuthentication() == null) {
        //     UserDetails user = jwtUserDetailsService.loadUserByUsername(ciamID);
        //     UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(user, null,
        //             user.getAuthorities());
        //     authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(httpServletRequest));
        //     SecurityContextHolder.getContext().setAuthentication(authentication);
        // }

        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }

}