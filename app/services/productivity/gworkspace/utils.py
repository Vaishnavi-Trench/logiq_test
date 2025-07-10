from pltfrm import PropX, Logger2 as Logger, MongoDBManager, AIManager, ElasticsearchManager
from typing import List, Dict, Any
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import base64
from google.oauth2 import service_account
from googleapiclient.discovery import build
import secrets
import string

class GworkspaceUtils:
    """Utility class for Google Workspace operations."""

    def __init__(self, intcid: str):
        """Initializes the GworkspaceUtils class."""
        Logger.info(f"Initializing GworkspaceUtils for intcid {intcid}")
        self.intcid = intcid
        self.main_db = PropX.get_property("module.integration.config.db")
        self.integration = PropX.get_property("module.integration.config.collection")
        self.toolsmetadata = PropX.get_property("module.integration.metadata.collection")
        self.templates_db = PropX.get_property("module.templates.collection")
        self.trenchrecords_db = PropX.get_property("module.trenchrun.collection")
        config = MongoDBManager.get_record_by_multiple_fields(
            self.main_db,
            self.integration,
            {
                "intcid": self.intcid,
                "type": "productivity",
                "vendor": "gworkspace",
                "recordType": "investigation",
            },
        )
        self.service_account_secret = config.get("service_account_secret", None)
        self.admin_email = config.get("admin_email", None)
        self.scopes = [
                "https://www.googleapis.com/auth/admin.directory.user",
                "https://www.googleapis.com/auth/gmail.send",
            ]
    def validate_config(self) -> bool:
        """Validate service account configuration and provide debugging info."""
        Logger.info("Validating GWorkspace service account configuration...")

        if not self.admin_email:
            Logger.error("Admin email is not configured.")
            return False
        Logger.info(f"Admin email configured: {self.admin_email}")

        if not self.service_account_secret:
            Logger.error("Service account secret is not configured.")
            return False

        try:
            # The secret is expected to be a JSON string
            sa_data = json.loads(self.service_account_secret)
            Logger.info("Service account secret loaded and parsed successfully.")

            Logger.info("Service account details:")
            Logger.info(f"   - Client ID: {sa_data.get('client_id', 'N/A')}")
            Logger.info(f"   - Client Email: {sa_data.get('client_email', 'N/A')}")
            Logger.info(f"   - Project ID: {sa_data.get('project_id', 'N/A')}")
            Logger.info(f"   - Type: {sa_data.get('type', 'N/A')}")

            # Check required fields
            required_fields = ["client_id", "client_email", "private_key", "type", "project_id"]
            missing_fields = [field for field in required_fields if field not in sa_data]

            if missing_fields:
                Logger.error(f"Missing required fields in service account secret: {missing_fields}")
                return False

            Logger.info("All required fields present in service account secret.")
            return True
        except json.JSONDecodeError as e:
            Logger.error(f"Invalid JSON in service account secret: {e}")
            return False
        except (TypeError, KeyError) as e:
            Logger.error(f"Error processing service account secret: {e}")
            return False
        
    def service_account_auth(self):
        """Authenticates with Google using service account credentials."""
        try:
            if not self.validate_config():
                Logger.error("Authentication failed due to invalid configuration.")
                return None

            sa_info = json.loads(self.service_account_secret)

            # Load service account credentials from the dictionary
            credentials = service_account.Credentials.from_service_account_info(
                sa_info, scopes=self.scopes
            )

            Logger.info("Service account credentials loaded successfully.")
            return credentials

        except Exception as e:
            Logger.error(f"Service account authentication failed: {e}")
            return None

    def delegated_auth(self):
        """Authenticates with Google Workspace using delegated service account credentials."""
        try:
            credentials = self.service_account_auth()
            if not credentials:
                return None

            # Delegate credentials to the admin user for domain-wide access
            delegated_credentials = credentials.with_subject(self.admin_email)

            Logger.info("Delegated credentials created successfully.")
            Logger.info(f"Delegated to: {self.admin_email}")
            Logger.info(f"Service account email: {delegated_credentials.service_account_email}")
            Logger.info(f"Scopes: {delegated_credentials.scopes}")

            return delegated_credentials

        except Exception as e:
            Logger.error(f"Delegated authentication failed: {e}")
            return None
        
    def test_connection(self):
        """Test delegated authentication and API access."""
        Logger.info(f"Testing delegated authentication for: {self.admin_email}")

        try:
            delegated_creds = self.delegated_auth()
            if not delegated_creds:
                Logger.error("Could not get delegated credentials for testing.")
                return None

            # Test by calling a simple API
            admin_service = build("admin", "directory_v1", credentials=delegated_creds)

            # Try to get user info for the delegated admin (should work if properly configured)
            try:
                user_info = admin_service.users().get(userKey=self.admin_email).execute()  # type: ignore[attr-defined]
                Logger.info("Successfully authenticated as delegated admin")
                Logger.info(f"Admin user: {user_info.get('primaryEmail', 'N/A')}")
                Logger.info(f"Admin name: {user_info.get('name', {}).get('fullName', 'N/A')}")
                return delegated_creds

            except Exception as api_error:
                Logger.error(f"API call failed with delegated credentials: {api_error}")
                Logger.info("TROUBLESHOOTING STEPS:")
                Logger.info("1. Enable domain-wide delegation for your service account:")
                Logger.info("   - Go to Google Cloud Console > IAM & Admin > Service Accounts")
                Logger.info("   - Find your service account and click 'Edit'")
                Logger.info("   - Check 'Enable Google Workspace Domain-wide Delegation'")
                Logger.info("   - Note the Client ID")
                Logger.info("2. Authorize the service account in Google Admin Console:")
                Logger.info("   - Go to Google Admin Console > Security > API controls")
                Logger.info("   - Click 'Domain-wide delegation'")
                Logger.info("   - Add your service account's Client ID")
                Logger.info(f"   - Add these scopes: {', '.join(self.scopes)}")
                Logger.info("3. Verify the delegated admin email has super admin privileges")
                Logger.info(
                    f"   - Check that {self.admin_email} is a super admin in Google Admin Console"
                )
                return None

        except Exception as e:
            Logger.error(f"Delegated authentication test failed: {e}")
            return None
        
    def get_user_info(self, email_address: str) -> Dict[str, Any] | None:
        """Get user information to verify a Google Workspace account exists."""
        Logger.info(f"Getting user info for: {email_address}")

        try:
            delegated_creds = self.delegated_auth()
            if not delegated_creds:
                Logger.error(f"Could not get delegated credentials to fetch user info for {email_address}.")
                return None

            admin_service = build("admin", "directory_v1", credentials=delegated_creds)
            user_info = admin_service.users().get(userKey=email_address).execute()  # type: ignore[attr-defined]

            Logger.info(f"User found: {user_info.get('primaryEmail', 'N/A')}")
            Logger.info(f"User name: {user_info.get('name', {}).get('fullName', 'N/A')}")
            Logger.info(f"User suspended: {user_info.get('suspended', False)}")

            return user_info

        except Exception as e:
            Logger.error(f"Could not get user info for {email_address}: {e}")
            return None

    def generate_random_password(self, length: int = 16) -> str:
        """Generate a random password with specified length."""
        # Define character sets
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        special_chars = "@#$*"
        # Ensure password has at least one character from each set
        password = [
            secrets.choice(lowercase),
            secrets.choice(uppercase),
            secrets.choice(digits),
            secrets.choice(special_chars),
        ]
        # Fill the rest of the password length with random characters
        all_chars = lowercase + uppercase + digits + special_chars
        for _ in range(length - 4):
            password.append(secrets.choice(all_chars))
        # Shuffle the password list and return as string
        secrets.SystemRandom().shuffle(password)
        return "".join(password)

    def create_email_message(
        self, sender: str, to: str, subject: str, message_text: str
    ) -> Dict[str, str] | None:
        """Creates a base64-encoded email message."""
        try:
            message = MIMEMultipart()
            message["to"] = to
            message["from"] = sender
            message["subject"] = subject

            msg = MIMEText(message_text)
            message.attach(msg)

            raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
            return {"raw": raw_message}
        except Exception as e:
            Logger.error(f"Failed to create email message: {e}")
            return None
        
    def get_email_from_mongo(self) -> Any:
        """Get the email from MongoDB."""
        Logger.info(f"Fetching email from MongoDB for intcid {self.intcid}")
        filter = {
            "intcid": self.intcid,
            "recordType": "containment",
            "type": "containment_details",
        }
        record = MongoDBManager.get_record_by_multiple_fields(
            self.main_db,
            self.integration,
            filter
        )
        if not record:
            Logger.error("No record found in MongoDB for the given intcid.")
            return {"status": False, "description": "No record found in MongoDB."}
        if not record['containment']:
            description = "Containment is not enabled in the integration."
            return {"status": False, "description": description}


        email = record.get("gworkspace", "")
        if not email:
            Logger.error("Email not found in the record.")
            return {"status": True, "email": "", "description": "Email not found in the record."}

        return {"status": True, "email": email, "description": "Using test credentials."}