"""Tests for Organization and Federation SDK methods."""

import pytest
import httpx
import respx

BASE_URL = "http://localhost:8080"

# 32-char lowercase hex orgIDs match the format produced by
# processOrgRegister (sha256 first-16-bytes hex), which `get_org()` sniffs
# via `_looks_like_org_id` to route directly to /v1/org/{org_id} instead of
# the new /v1/org/by-name/{name} endpoint added in v6.6.9.
ORG_ID = "01234567890123456789012345678901"
TARGET_ORG_ID = "fedcba9876543210fedcba9876543210"
FED_ID = "fed-abc-123"
AGENT_ID = "b" * 64


@pytest.fixture
def client(agent_identity):
    from sage_sdk.client import SageClient
    return SageClient(base_url=BASE_URL, identity=agent_identity)


@pytest.fixture
def mock_api():
    with respx.mock(base_url=BASE_URL, assert_all_called=False) as respx_mock:
        yield respx_mock


# --- Organization: Sync client tests ---


def test_register_org(client, mock_api):
    mock_api.post("/v1/org/register").mock(
        return_value=httpx.Response(201, json={
            "status": "registered",
            "org_id": ORG_ID,
            "tx_hash": "deadbeef" * 8,
        })
    )
    result = client.register_org(name="Test Org", description="A test organization")
    assert result["status"] == "registered"
    assert result["org_id"] == ORG_ID


def test_get_org(client, mock_api):
    org_data = {
        "org_id": ORG_ID,
        "name": "Test Org",
        "description": "A test organization",
        "owner_agent": "a" * 64,
        "created_height": 10,
    }
    mock_api.get(f"/v1/org/{ORG_ID}").mock(
        return_value=httpx.Response(200, json=org_data)
    )
    result = client.get_org(ORG_ID)
    assert result["name"] == "Test Org"
    assert result["org_id"] == ORG_ID


def test_get_org_by_name_routes_to_by_name_endpoint(client, mock_api):
    # Non-hex identifier must route to /v1/org/by-name/{name} and unwrap the
    # single match. Locks in the v6.6.9 hex-vs-name sniffing in get_org.
    org_data = {
        "org_id": ORG_ID,
        "name": "levelup",
        "description": "",
        "owner_agent": "a" * 64,
        "created_height": 10,
    }
    mock_api.get("/v1/org/by-name/levelup").mock(
        return_value=httpx.Response(200, json={"orgs": [org_data]})
    )
    result = client.get_org("levelup")
    assert result["org_id"] == ORG_ID
    assert result["name"] == "levelup"


def test_get_org_by_name_ambiguous_match_raises(client, mock_api):
    # Multiple admins registering the same name produces multiple orgIDs;
    # get_org cannot disambiguate, must raise ValueError so callers fall back
    # to list_orgs_by_name.
    mock_api.get("/v1/org/by-name/levelup").mock(
        return_value=httpx.Response(200, json={"orgs": [
            {"org_id": "0" * 32, "name": "levelup", "owner_agent": "a" * 64, "created_height": 1},
            {"org_id": "1" * 32, "name": "levelup", "owner_agent": "b" * 64, "created_height": 2},
        ]})
    )
    with pytest.raises(ValueError):
        client.get_org("levelup")


def test_add_org_member(client, mock_api):
    mock_api.post(f"/v1/org/{ORG_ID}/member").mock(
        return_value=httpx.Response(201, json={
            "status": "added",
            "tx_hash": "deadbeef" * 8,
        })
    )
    result = client.add_org_member(ORG_ID, agent_id=AGENT_ID, clearance=2, role="admin")
    assert result["status"] == "added"


def test_add_org_member_defaults(client, mock_api):
    mock_api.post(f"/v1/org/{ORG_ID}/member").mock(
        return_value=httpx.Response(201, json={
            "status": "added",
            "tx_hash": "deadbeef" * 8,
        })
    )
    result = client.add_org_member(ORG_ID, agent_id=AGENT_ID)
    assert result["status"] == "added"


def test_remove_org_member(client, mock_api):
    mock_api.delete(f"/v1/org/{ORG_ID}/member/{AGENT_ID}").mock(
        return_value=httpx.Response(200, json={
            "status": "removed",
            "tx_hash": "cafebabe" * 8,
        })
    )
    result = client.remove_org_member(ORG_ID, AGENT_ID)
    assert result["status"] == "removed"


def test_set_org_clearance(client, mock_api):
    mock_api.post(f"/v1/org/{ORG_ID}/clearance").mock(
        return_value=httpx.Response(200, json={
            "status": "updated",
            "tx_hash": "deadbeef" * 8,
        })
    )
    result = client.set_org_clearance(ORG_ID, agent_id=AGENT_ID, clearance=3)
    assert result["status"] == "updated"


def test_list_org_members(client, mock_api):
    members = [
        {"org_id": ORG_ID, "agent_id": AGENT_ID, "clearance": 2, "role": "admin"},
        {"org_id": ORG_ID, "agent_id": "c" * 64, "clearance": 1, "role": "member"},
    ]
    mock_api.get(f"/v1/org/{ORG_ID}/members").mock(
        return_value=httpx.Response(200, json=members)
    )
    result = client.list_org_members(ORG_ID)
    assert len(result) == 2
    assert result[0]["role"] == "admin"
    assert result[1]["clearance"] == 1


# --- Federation: Sync client tests ---


def test_propose_federation(client, mock_api):
    mock_api.post("/v1/federation/propose").mock(
        return_value=httpx.Response(201, json={
            "status": "proposed",
            "tx_hash": "deadbeef" * 8,
        })
    )
    result = client.propose_federation(
        target_org_id=TARGET_ORG_ID,
        allowed_domains=["crypto", "vuln_intel"],
        allowed_depts=["engineering"],
        max_clearance=3,
        expires_at=0,
        requires_approval=True,
        proposer_org_id=ORG_ID,
    )
    assert result["status"] == "proposed"


def test_propose_federation_defaults(client, mock_api):
    mock_api.post("/v1/federation/propose").mock(
        return_value=httpx.Response(201, json={
            "status": "proposed",
            "tx_hash": "deadbeef" * 8,
        })
    )
    result = client.propose_federation(target_org_id=TARGET_ORG_ID)
    assert result["status"] == "proposed"


def test_approve_federation(client, mock_api):
    mock_api.post(f"/v1/federation/{FED_ID}/approve").mock(
        return_value=httpx.Response(200, json={
            "status": "approved",
            "tx_hash": "cafebabe" * 8,
        })
    )
    result = client.approve_federation(FED_ID)
    assert result["status"] == "approved"


def test_revoke_federation(client, mock_api):
    mock_api.post(f"/v1/federation/{FED_ID}/revoke").mock(
        return_value=httpx.Response(200, json={
            "status": "revoked",
            "tx_hash": "cafebabe" * 8,
        })
    )
    result = client.revoke_federation(FED_ID, reason="Agreement expired")
    assert result["status"] == "revoked"


def test_revoke_federation_no_reason(client, mock_api):
    mock_api.post(f"/v1/federation/{FED_ID}/revoke").mock(
        return_value=httpx.Response(200, json={
            "status": "revoked",
            "tx_hash": "cafebabe" * 8,
        })
    )
    result = client.revoke_federation(FED_ID)
    assert result["status"] == "revoked"


def test_get_federation(client, mock_api):
    fed_data = {
        "federation_id": FED_ID,
        "source_org_id": ORG_ID,
        "target_org_id": TARGET_ORG_ID,
        "allowed_domains": ["crypto"],
        "allowed_depts": ["engineering"],
        "max_clearance": 2,
        "status": "active",
    }
    mock_api.get(f"/v1/federation/{FED_ID}").mock(
        return_value=httpx.Response(200, json=fed_data)
    )
    result = client.get_federation(FED_ID)
    assert result["federation_id"] == FED_ID
    assert result["status"] == "active"


def test_list_federations(client, mock_api):
    feds = [
        {
            "federation_id": FED_ID,
            "source_org_id": ORG_ID,
            "target_org_id": TARGET_ORG_ID,
            "status": "active",
        },
        {
            "federation_id": "fed-xyz-456",
            "source_org_id": ORG_ID,
            "target_org_id": "test-org-3",
            "status": "active",
        },
    ]
    mock_api.get(f"/v1/federation/active/{ORG_ID}").mock(
        return_value=httpx.Response(200, json=feds)
    )
    result = client.list_federations(ORG_ID)
    assert len(result) == 2
    assert result[0]["federation_id"] == FED_ID


# --- Async client tests ---


import pytest_asyncio


@pytest_asyncio.fixture
async def async_client(agent_identity):
    from sage_sdk.async_client import AsyncSageClient
    client = AsyncSageClient(base_url=BASE_URL, identity=agent_identity)
    yield client
    await client.close()


@pytest.mark.asyncio
async def test_async_register_org(async_client, mock_api):
    mock_api.post("/v1/org/register").mock(
        return_value=httpx.Response(201, json={
            "status": "registered",
            "org_id": ORG_ID,
            "tx_hash": "deadbeef" * 8,
        })
    )
    result = await async_client.register_org(name="Test Org", description="Async test org")
    assert result["status"] == "registered"
    assert result["org_id"] == ORG_ID


@pytest.mark.asyncio
async def test_async_add_org_member(async_client, mock_api):
    mock_api.post(f"/v1/org/{ORG_ID}/member").mock(
        return_value=httpx.Response(201, json={
            "status": "added",
            "tx_hash": "deadbeef" * 8,
        })
    )
    result = await async_client.add_org_member(ORG_ID, agent_id=AGENT_ID)
    assert result["status"] == "added"


@pytest.mark.asyncio
async def test_async_remove_org_member(async_client, mock_api):
    mock_api.delete(f"/v1/org/{ORG_ID}/member/{AGENT_ID}").mock(
        return_value=httpx.Response(200, json={
            "status": "removed",
            "tx_hash": "cafebabe" * 8,
        })
    )
    result = await async_client.remove_org_member(ORG_ID, AGENT_ID)
    assert result["status"] == "removed"


@pytest.mark.asyncio
async def test_async_propose_federation(async_client, mock_api):
    mock_api.post("/v1/federation/propose").mock(
        return_value=httpx.Response(201, json={
            "status": "proposed",
            "tx_hash": "deadbeef" * 8,
        })
    )
    result = await async_client.propose_federation(
        target_org_id=TARGET_ORG_ID,
        allowed_domains=["crypto"],
        proposer_org_id=ORG_ID,
    )
    assert result["status"] == "proposed"


@pytest.mark.asyncio
async def test_async_approve_federation(async_client, mock_api):
    mock_api.post(f"/v1/federation/{FED_ID}/approve").mock(
        return_value=httpx.Response(200, json={
            "status": "approved",
            "tx_hash": "cafebabe" * 8,
        })
    )
    result = await async_client.approve_federation(FED_ID)
    assert result["status"] == "approved"


@pytest.mark.asyncio
async def test_async_list_federations(async_client, mock_api):
    mock_api.get(f"/v1/federation/active/{ORG_ID}").mock(
        return_value=httpx.Response(200, json=[
            {
                "federation_id": FED_ID,
                "source_org_id": ORG_ID,
                "target_org_id": TARGET_ORG_ID,
                "status": "active",
            },
        ])
    )
    result = await async_client.list_federations(ORG_ID)
    assert len(result) == 1
    assert result[0]["federation_id"] == FED_ID
