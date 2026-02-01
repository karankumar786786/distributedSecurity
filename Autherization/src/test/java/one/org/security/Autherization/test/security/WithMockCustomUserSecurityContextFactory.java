package one.org.security.Autherization.test.security;

import org.bson.types.ObjectId;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.support.WithSecurityContextFactory;

import one.org.security.Autherization.core.domain.entity.UserMockEntity;

public class WithMockCustomUserSecurityContextFactory implements WithSecurityContextFactory<WithMockCustomUser> {

    @Override
    public SecurityContext createSecurityContext(WithMockCustomUser annotation) {
        SecurityContext context = SecurityContextHolder.createEmptyContext();

        UserMockEntity user = UserMockEntity.builder()
                .id(new ObjectId(annotation.userId()))
                .username(annotation.username())
                .password("password")
                .build();

        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(user, "password",
                user.getAuthorities());
        context.setAuthentication(auth);
        return context;
    }
}
