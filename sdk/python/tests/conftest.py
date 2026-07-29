import pytest
from unittest.mock import MagicMock

# These fixtures will work once the SDK is installed


@pytest.fixture
def agent_identity():
    """Create a test Ed25519 identity."""
    from sage_sdk.auth import AgentIdentity
    return AgentIdentity.generate()


@pytest.fixture
def second_identity():
    """Create a second test identity for multi-agent tests."""
    from sage_sdk.auth import AgentIdentity
    return AgentIdentity.generate()


@pytest.fixture
def sample_memory():
    """Sample memory record data."""
    return {
        "memory_id": "550e8400-e29b-41d4-a716-446655440000",
        "submitting_agent": "a" * 64,
        "content": "Flask web challenges with SQLi require prepared statements bypass",
        "content_hash": "abc123",
        "memory_type": "fact",
        "domain_tag": "challenge_generation",
        "confidence_score": 0.85,
        "status": "proposed",
        "parent_hash": None,
        "created_at": "2024-01-01T00:00:00Z",
        "committed_at": None,
        "deprecated_at": None,
    }


@pytest.fixture
def sample_submit_response():
    """Sample memory submit response."""
    return {
        "memory_id": "550e8400-e29b-41d4-a716-446655440000",
        "tx_hash": "deadbeef" * 8,
        "status": "proposed",
        "committed": True,
        "committed_height": 42,
    }


@pytest.fixture
def sample_query_response(sample_memory):
    """Sample query response."""
    return {
        "results": [sample_memory],
        "next_cursor": None,
        "total_count": 1,
    }


@pytest.fixture
def sample_error_response():
    """Sample RFC 7807 error response."""
    return {
        "type": "https://sage.example.com/errors/not-found",
        "title": "Memory Not Found",
        "status": 404,
        "detail": "Memory with ID xyz does not exist",
        "instance": "/v1/memory/xyz",
    }
