package one.org.security.Autherization.core.domain.entity;

import java.util.Collection;
import java.util.Collections;

import org.bson.types.ObjectId;
import org.springframework.security.core.GrantedAuthority;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Builder
@Data
@AllArgsConstructor
public class UserMockEntity {
    private ObjectId id;
    private String username;

    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.emptyList();
    }
}
