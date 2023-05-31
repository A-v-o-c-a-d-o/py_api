from pyjwt import JWT

def generate_jwt_token(username: str, password: str) -> str:
    """Generates a JWT token for the given username and password."""

    # Create a JWT claims object
    claims = {
        "username": username,
        "password": password,
    }

    # Create a JWT token
    token = JWT.encode(claims, "secret", algorithm="HS256")

    return token

def verify_jwt_token(token: str) -> dict:
    """Verifies a JWT token and returns the claims object."""

    # Decode the JWT token
    claims = JWT.decode(token, "secret", algorithms=["HS256"])

    return claims