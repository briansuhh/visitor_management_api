import requests
from jose import jwt
from rest_framework import authentication, exceptions
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache


class KeycloakAuthentication(authentication.BaseAuthentication):
    JWSKS_CACHE_KEY = "keycloak_jwks"
    JWSKS_CACHE_TTL = 60 * 60  # 1 hour

    def get_jwks(self):
        jwks = cache.get(self.JWSKS_CACHE_KEY)
        if not jwks:
            try:
                response = requests.get(settings.KEYCLOAK_JWKS_URL, timeout=5)
                response.raise_for_status()
                jwks = response.json()
                cache.set(self.JWSKS_CACHE_KEY, jwks, self.JWSKS_CACHE_TTL)
            except Exception as e:
                raise exceptions.AuthenticationFailed(f"Failed to fetch JWKS: {str(e)}")
        return jwks
    
    def authenticate(self, request):
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return None
        
        token = auth_header.split(" ")[1]

        try:
            unverified_header = jwt.get_unverified_header(token)
            kid = unverified_header.get("kid")
            if not kid:
                raise exceptions.AuthenticationFailed("Token header missing 'kid'")

            jwks = self.get_jwks()
            # Filter for signature keys only
            sig_keys = [k for k in jwks.get("keys", []) if k.get("use") == "sig" or k.get("alg") == "RS256"]
            key = next((k for k in sig_keys if k.get("kid") == kid), None)
            
            # If key not found, refresh JWKS and try again
            if not key:
                cache.delete(self.JWSKS_CACHE_KEY)
                jwks = self.get_jwks()
                sig_keys = [k for k in jwks.get("keys", []) if k.get("use") == "sig" or k.get("alg") == "RS256"]
                key = next((k for k in sig_keys if k.get("kid") == kid), None)
                
                if not key:
                    # Debug: log available kids
                    available_kids = [k.get("kid") for k in sig_keys]
                    sig_kids = [k.get("kid") for k in sig_keys]
                    raise exceptions.AuthenticationFailed(
                        f"Public key not found in JWKS. Token kid: {kid}, All kids: {available_kids}, Sig kids: {sig_kids}"
                    )
                
            # Decode and verify the token
            claims = jwt.decode(
                token,
                key,
                algorithms=["RS256"],
                audience=settings.KEYCLOAK_AUDIENCE,
                issuer=settings.KEYCLOAK_ISSUER,
            )

        except jwt.ExpiredSignatureError:
            raise exceptions.AuthenticationFailed("Token has expired")
        except jwt.JWTClaimsError as e:
            raise exceptions.AuthenticationFailed(f"Invalid claims: {e}")
        except Exception as e:
            raise exceptions.AuthenticationFailed(f"Invalid token: {e}")
        
        # Extract user info from claims
        keycloak_id = claims.get("sub")
        if not keycloak_id:
            raise exceptions.AuthenticationFailed("Token missing 'sub' claim")
        
        username = claims.get("preferred_username", f"user_{keycloak_id[:8]}")
        email = claims.get("email", "")
        first_name = claims.get("given_name", "")
        middle_name = claims.get("middle_name", "")
        last_name = claims.get("family_name", "")
        roles = claims.get("realm_access", {}).get("roles", [])

        # Get or create local user
        User = get_user_model()
        user, created = User.objects.get_or_create(
            keycloak_id=keycloak_id,
            defaults={
                "username": username,
                "email": email,
                "first_name": first_name,
                "last_name": last_name,
                "middle_name": middle_name,
                "roles": roles,
            },
        )

        # Sync fields if user already exists
        if not created:
            updated = False
            for attr, value in [
                ("username", username),
                ("email", email),
                ("first_name", first_name),
                ("middle_name", middle_name),
                ("last_name", last_name),
                ("roles", roles),
            ]:
                if getattr(user, attr) != value:
                    setattr(user, attr, value)
                    updated = True
            if updated:
                user.save()

        # Attach claims & roles to user for easy access in views
        user.keycloak_claims = claims
        user.keycloak_roles = roles

        return (user, None)