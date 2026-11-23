import json
from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import AwareDatetime, BeforeValidator, Field, StringConstraints, field_validator, model_validator
from pydantic.json_schema import models_json_schema

from .device_schemas import Wire

KeyID = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{1,40}$")]
PublicKey = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{43}$")]
Signature = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{86}$")]
Fingerprint = Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{64}$")]
PayloadBytes = Annotated[str, StringConstraints(min_length=1, max_length=16384, pattern=r"^[A-Za-z0-9_-]+$")]
Sequence = Annotated[int, Field(strict=True, ge=1, le=2**63 - 1)]


def validate_protocol_version(value):
    if type(value) is not int:
        raise ValueError("protocol version must be an integer")
    return value


def validate_timestamp(value):
    if isinstance(value, str):
        return datetime.fromisoformat(value)
    if not isinstance(value, datetime):
        raise ValueError("timestamp must be an ISO-8601 string")
    return value


ProtocolVersion = Annotated[Literal[1], BeforeValidator(validate_protocol_version)]
Timestamp = Annotated[AwareDatetime, BeforeValidator(validate_timestamp)]


class SignedGrant(Wire):
    version: ProtocolVersion
    kid: KeyID
    payload: PayloadBytes
    signature: Signature


class GrantPayload(Wire):
    license_id: UUID
    activation_id: UUID
    instance_id: UUID
    instance_key_sha256: Fingerprint
    edition: Literal["business", "enterprise"]
    device_limit: Annotated[int, Field(strict=True, ge=1, le=1_000_000)]
    features: Annotated[list[Literal["inventory", "catalog", "deployments"]], Field(max_length=3, json_schema_extra={"uniqueItems": True})]
    issue_number: Sequence
    issued_at: Timestamp
    not_before: Timestamp
    expires_at: Timestamp
    grace_until: Timestamp

    @field_validator("features")
    @classmethod
    def distinct_features(cls, features):
        if len(features) != len(set(features)):
            raise ValueError("duplicate license feature")
        return features

    @model_validator(mode="after")
    def validate_window(self):
        if not self.issued_at <= self.not_before < self.expires_at <= self.grace_until:
            raise ValueError("invalid grant validity window")
        return self


class ChallengeRequest(Wire):
    protocol: ProtocolVersion
    instance_id: UUID
    instance_public_key: PublicKey


class Challenge(Wire):
    challenge_id: UUID
    nonce: PublicKey
    expires_at: Timestamp


class ActivationRequest(ChallengeRequest):
    request_id: UUID
    challenge_id: UUID
    proof: Signature


def cloud_contract() -> dict:
    models = (ChallengeRequest, Challenge, ActivationRequest, SignedGrant, GrantPayload)
    _, definitions = models_json_schema([(model, "validation") for model in models],
                                        ref_template="#/components/schemas/{model}")
    endpoints = {
        "/v1/activation/challenge": ("createChallenge", "ChallengeRequest", "Challenge"),
        "/v1/activation/complete": ("completeActivation", "ActivationRequest", "SignedGrant"),
    }
    paths = {}
    for path, (operation, request, response) in endpoints.items():
        paths[path] = {"post": {
            "operationId": operation,
            "security": [{"ActivationAuthorization": []}],
            "requestBody": {"required": True, "content": {"application/json": {
                "schema": {"$ref": f"#/components/schemas/{request}"},
            }}},
            "responses": {
                "200": {"description": "Successful response", "content": {"application/json": {
                    "schema": {"$ref": f"#/components/schemas/{response}"},
                }}},
                "401": {"description": "Activation credential missing or invalid"},
                "403": {"description": "Activation or proof rejected"},
                "409": {"description": "Challenge consumed or request identity conflict"},
                "422": {"description": "Invalid protocol payload"},
                "429": {"description": "Activation rate limit reached"},
            },
        }}
    return {
        "openapi": "3.1.0",
        "info": {"title": "DeployCore Cloud Activation", "version": "1.0.0-draft",
                 "description": "Contract for the future activation service."},
        "paths": paths,
        "components": {
            "schemas": definitions["$defs"],
            "securitySchemes": {
                "ActivationAuthorization": {"type": "http", "scheme": "bearer",
                                            "description": "Activation credential bound to a Cloud entitlement."},
            },
        },
    }


if __name__ == "__main__":
    print(json.dumps(cloud_contract(), indent=2, ensure_ascii=False))
