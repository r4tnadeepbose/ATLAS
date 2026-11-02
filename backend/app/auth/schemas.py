from pydantic import BaseModel, EmailStr, Field


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)
    mfa_code: str | None = Field(default=None, max_length=10)


class BootstrapRequest(BaseModel):
    organization_name: str = Field(min_length=2, max_length=200)
    full_name: str = Field(min_length=2, max_length=200)
    email: EmailStr
    password: str = Field(min_length=12, max_length=256)


class RefreshRequest(BaseModel):
    refresh_token: str


class MfaVerifyRequest(BaseModel):
    code: str = Field(min_length=6, max_length=10)


class MfaDisableRequest(BaseModel):
    password: str
    code: str


class UserCreateRequest(BaseModel):
    email: EmailStr
    full_name: str = Field(min_length=2, max_length=200)
    password: str = Field(min_length=12, max_length=256)
    role: str = Field(default="developer")
    title: str | None = None
    team_id: str | None = None


class UserUpdateRequest(BaseModel):
    full_name: str | None = None
    title: str | None = None
    is_active: bool | None = None


class RoleChangeRequest(BaseModel):
    role: str


class TeamCreateRequest(BaseModel):
    name: str = Field(min_length=2, max_length=150)
    description: str | None = None
    business_unit: str | None = None


class OrganizationUpdateRequest(BaseModel):
    name: str | None = None
    settings: dict | None = None


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=12, max_length=256)
