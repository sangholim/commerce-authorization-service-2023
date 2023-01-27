package moe.saru.keycloak.modules.apple;

import org.keycloak.OAuth2Constants;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.ServerECDSASignatureSignerContext;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.events.EventBuilder;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.JsonWebToken;

import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.core.Response;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class AppleIdentityProvider extends OIDCIdentityProvider implements SocialIdentityProvider<OIDCIdentityProviderConfig> {

    public AppleIdentityProvider(KeycloakSession session, AppleIdentityProviderConfig config) {
        super(session, config);
        config.setAuthorizationUrl("https://appleid.apple.com/auth/authorize?response_mode=form_post");
        config.setTokenUrl("https://appleid.apple.com/auth/token");
    }

    @Override
    public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
        return new OIDCEndpoint(callback, realm, event);
    }

    @Override
    public SimpleHttp authenticateTokenRequest(SimpleHttp tokenRequest) {
        AppleIdentityProviderConfig config = (AppleIdentityProviderConfig) getConfig();
        tokenRequest.param(OAUTH2_PARAMETER_CLIENT_ID, config.getClientId());
        String base64PrivateKey = config.getClientSecret();
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            byte[] pkc8ePrivateKey = Base64.getDecoder().decode(base64PrivateKey);
            PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(pkc8ePrivateKey);
            PrivateKey privateKey = keyFactory.generatePrivate(keySpecPKCS8);

            KeyWrapper keyWrapper = new KeyWrapper();
            keyWrapper.setAlgorithm(Algorithm.ES256);
            keyWrapper.setKid(config.getKeyId());
            keyWrapper.setPrivateKey(privateKey);
            SignatureSignerContext signer = new ServerECDSASignatureSignerContext(keyWrapper);

            long currentTime = Time.currentTime();
            JsonWebToken token = new JsonWebToken();
            token.issuer(config.getTeamId());
            token.iat(currentTime);
            token.exp(currentTime + 15 * 60);
            token.audience("https://appleid.apple.com");
            token.subject(config.getClientId());
            String clientSecret = new JWSBuilder().jsonContent(token).sign(signer);

            tokenRequest.param(OAUTH2_PARAMETER_CLIENT_SECRET, clientSecret);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            logger.errorf("Failed to generate client secret: %s", e);
        }

        return tokenRequest;
    }

    @Override
    protected String getDefaultScopes() {
        return "email name";
    }

    protected class OIDCEndpoint extends OIDCIdentityProvider.OIDCEndpoint {
        public OIDCEndpoint(AuthenticationCallback callback, RealmModel realm, EventBuilder event) {
            super(callback, realm, event);
        }

        @POST
        public Response authResponse(
                @FormParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_STATE) String state,
                @FormParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_CODE) String authorizationCode,
                @FormParam(OAuth2Constants.ERROR) String error) {
            return super.authResponse(state, authorizationCode, error);
        }
    }
}
