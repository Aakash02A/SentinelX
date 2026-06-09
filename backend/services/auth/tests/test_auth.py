import pytest
from httpx import AsyncClient
from sentinelx_shared.models.user import User
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


@pytest.mark.asyncio
async def test_register_user(client: AsyncClient, db_session: AsyncSession):
    # Test valid registration
    response = await client.post(
        "/auth/register",
        json={
            "email": "testuser@example.com",
            "password": "Password123!!",
            "full_name": "Test User",
        },
    )
    assert response.status_code == 210 or response.status_code == 201
    data = response.json()
    assert data["email"] == "testuser@example.com"
    assert data["role"] == "user"

    # Verify user in database
    result = await db_session.execute(
        select(User).where(User.email == "testuser@example.com")
    )
    user = result.scalar_one_or_none()
    assert user is not None
    assert user.full_name == "Test User"


@pytest.mark.asyncio
async def test_register_invalid_password(client: AsyncClient):
    # Weak password check (no digit/upper/special etc)
    response = await client.post(
        "/auth/register",
        json={
            "email": "weak@example.com",
            "password": "weak",
            "full_name": "Weak User",
        },
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_login_user(client: AsyncClient):
    # Login user
    response = await client.post(
        "/auth/login",
        data={
            "username": "testuser@example.com",
            "password": "Password123!!",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["requires_mfa"] is False


@pytest.mark.asyncio
async def test_get_profile(client: AsyncClient):
    # First login to get token
    login_response = await client.post(
        "/auth/login",
        data={
            "username": "testuser@example.com",
            "password": "Password123!!",
        },
    )
    token = login_response.json()["access_token"]

    # Get profile
    response = await client.get(
        "/users/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == "testuser@example.com"
    assert data["full_name"] == "Test User"
