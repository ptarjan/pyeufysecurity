"""Define tests for the API module."""

from unittest.mock import MagicMock

from eufy_security.api import API, DEFAULT_HEADERS, SERVER_PUBLIC_KEY
from eufy_security.device import Camera

from .common import TEST_EMAIL, TEST_PASSWORD, load_json_fixture


class TestAPIInitialization:
    """Tests for API initialization."""

    def test_api_init_basic(self):
        """Test API initializes with basic parameters."""
        session = MagicMock()
        api = API(TEST_EMAIL, TEST_PASSWORD, session)

        assert api._email == TEST_EMAIL
        assert api._password == TEST_PASSWORD
        assert api._session is session
        assert api._country == "US"
        assert api._token is None
        assert api._api_base is None
        assert api.cameras == {}
        assert api.stations == {}

    def test_api_init_with_country(self):
        """Test API initializes with custom country."""
        session = MagicMock()
        api = API(TEST_EMAIL, TEST_PASSWORD, session, country="DE")

        assert api._country == "DE"

    def test_api_generates_ecdh_keys(self):
        """Test API generates ECDH key pair on init."""
        session = MagicMock()
        api = API(TEST_EMAIL, TEST_PASSWORD, session)

        # Should have private and public keys
        assert api._private_key is not None
        assert api._public_key is not None
        assert api._client_public_bytes is not None

        # Public key should be 65 bytes (uncompressed point format)
        assert len(api._client_public_bytes) == 65

    def test_api_computes_login_shared_secret(self):
        """Test API computes shared secret with server public key."""
        session = MagicMock()
        api = API(TEST_EMAIL, TEST_PASSWORD, session)

        # Should have computed shared secret for login
        assert api._login_shared_secret is not None
        assert len(api._login_shared_secret) == 32  # 256-bit shared secret

    def test_api_response_shared_secret_initially_none(self):
        """Test response shared secret is None until login."""
        session = MagicMock()
        api = API(TEST_EMAIL, TEST_PASSWORD, session)

        assert api._response_shared_secret is None
        assert api._server_public_key_hex is None


class TestServerPublicKey:
    """Tests for server public key constant."""

    def test_server_public_key_length(self):
        """Test server public key is correct length."""
        # Uncompressed EC point: 1 byte prefix + 32 bytes X + 32 bytes Y = 65 bytes
        assert len(SERVER_PUBLIC_KEY) == 65

    def test_server_public_key_starts_with_04(self):
        """Test server public key has uncompressed point prefix."""
        # 0x04 indicates uncompressed point format
        assert SERVER_PUBLIC_KEY[0] == 0x04


class TestDefaultHeaders:
    """Tests for default headers."""

    def test_default_headers_has_required_fields(self):
        """Test default headers contain required fields."""
        required = ["App_version", "Os_type", "Os_version", "Language"]
        for field in required:
            assert field in DEFAULT_HEADERS

    def test_default_headers_android(self):
        """Test default headers mimic Android app."""
        assert DEFAULT_HEADERS["Os_type"] == "android"


class TestCameraFromFixture:
    """Tests for creating Camera objects from fixture data."""

    def test_camera_from_devices_list(self):
        """Test creating Camera from devices list fixture."""
        fixture = load_json_fixture("devices_list_response.json")
        device_info = fixture["data"][0]

        api = MagicMock()
        camera = Camera(api=api, camera_info=device_info)

        assert camera.serial == "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx1"
        assert camera.name == "Driveway"
        assert camera.model == "T8111"
        assert camera.hardware_version == "HAIYI-IMX323"
        assert camera.software_version == "1.9.3"
        assert camera.last_camera_image_url == "https://path/to/image.jpg"

    def test_multiple_cameras_from_fixture(self):
        """Test creating multiple cameras from fixture."""
        fixture = load_json_fixture("devices_list_response.json")
        api = MagicMock()

        cameras = {}
        for device_info in fixture["data"]:
            camera = Camera(api=api, camera_info=device_info)
            cameras[camera.serial] = camera

        assert len(cameras) == 2
        assert "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx1" in cameras
        assert "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx2" in cameras
        assert cameras["xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx1"].name == "Driveway"
        assert cameras["xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx2"].name == "Patio"


class TestErrorResponses:
    """Tests for error response handling using fixtures."""

    def test_invalid_email_response(self):
        """Test invalid email response fixture has correct format."""
        fixture = load_json_fixture("login_failure_invalid_email_response.json")
        assert fixture["code"] == 26006
        assert "email" in fixture["msg"].lower()

    def test_invalid_password_response(self):
        """Test invalid password response fixture has correct format."""
        fixture = load_json_fixture("login_failure_invalid_password_response.json")
        assert fixture["code"] == 26006
        assert "password" in fixture["msg"].lower() or "incorrect" in fixture["msg"].lower()

    def test_empty_response(self):
        """Test empty response fixture is empty dict."""
        fixture = load_json_fixture("empty_response.json")
        assert fixture == {} or fixture.get("data") is None


class TestStreamResponses:
    """Tests for stream response fixtures."""

    def test_start_stream_response(self):
        """Test start stream response has URL."""
        fixture = load_json_fixture("start_stream_response.json")
        assert fixture["code"] == 0
        assert "url" in fixture.get("data", {})

    def test_stop_stream_response(self):
        """Test stop stream response is success."""
        fixture = load_json_fixture("stop_stream_response.json")
        assert fixture["code"] == 0
