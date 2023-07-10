import webbrowser

from fastapi import status
from fastapi.testclient import TestClient

from ecom.settings import settings


def test_should_register_with_google_oauth_correctly(
    client: TestClient,
):
    client_id = settings.auth.google_oauth.client_id
    url = f"https://accounts.google.com/o/oauth2/v2/auth?scope=email&response_type=code&redirect_uri=http%3A//127.0.0.1%3A8000/auth/google-oauth&client_id={client_id}"
    webbrowser.open(url)
    code = input("Enter the code: ")
    response = client.get(f"/auth/google-oauth?code={code}")
    assert response.status_code == status.HTTP_200_OK
    assert "access_token" in response.json()
