"""
Secure Configuration Manager

Handles loading, saving, and encrypting configuration files.
"""

import logging
from typing import Dict, Any, Optional
import yaml
from pathlib import Path
from cryptography.fernet import Fernet
import structlog
import os

logger = structlog.get_logger(__name__)


class ConfigManager:
    """
    Secure configuration manager with encryption support.

    Features:
    - YAML configuration loading/saving
    - Encryption for sensitive fields
    - Environment variable support
    - Configuration validation
    """

    def __init__(self, config_path: str = "config/config.yaml"):
        """
        Initialize configuration manager.

        Args:
            config_path: Path to configuration file
        """
        self.config_path = Path(config_path)
        self.encryption_key = self._get_or_create_key()
        self.cipher = Fernet(self.encryption_key)

        logger.info("config_manager_initialized", config_path=str(self.config_path))

    def _get_or_create_key(self) -> bytes:
        """Get or create encryption key."""
        key_path = Path("config/.encryption_key")
        key_path.parent.mkdir(parents=True, exist_ok=True)

        if key_path.exists():
            with open(key_path, "rb") as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(key_path, "wb") as f:
                f.write(key)
            key_path.chmod(0o600)  # Restrict permissions
            logger.info("encryption_key_generated")
            return key

    def load_config(self) -> Dict[str, Any]:
        """
        Load configuration from file.

        Returns:
            Configuration dictionary
        """
        if not self.config_path.exists():
            logger.warning("config_not_found", path=str(self.config_path))
            return self._get_default_config()

        try:
            with open(self.config_path, "r") as f:
                config = yaml.safe_load(f)

            # Decrypt sensitive fields
            config = self._decrypt_config(config)

            # Override with environment variables
            config = self._apply_env_overrides(config)

            logger.info("config_loaded", keys=list(config.keys()))
            return config

        except Exception as e:
            logger.error("config_load_failed", error=str(e))
            return self._get_default_config()

    def save_config(self, config: Dict[str, Any]):
        """
        Save configuration to file.

        Args:
            config: Configuration dictionary to save
        """
        try:
            # Encrypt sensitive fields
            config_to_save = self._encrypt_config(config)

            self.config_path.parent.mkdir(parents=True, exist_ok=True)

            with open(self.config_path, "w") as f:
                yaml.dump(config_to_save, f, default_flow_style=False)

            self.config_path.chmod(0o600)  # Restrict permissions

            logger.info("config_saved", path=str(self.config_path))

        except Exception as e:
            logger.error("config_save_failed", error=str(e))
            raise

    def _encrypt_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Encrypt sensitive configuration fields."""
        sensitive_fields = ["api_key", "password", "token", "secret"]
        encrypted_config = config.copy()

        for key, value in config.items():
            if any(sf in key.lower() for sf in sensitive_fields):
                if isinstance(value, str) and value:
                    encrypted_config[key] = self.cipher.encrypt(value.encode()).decode()

        return encrypted_config

    def _decrypt_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Decrypt sensitive configuration fields."""
        sensitive_fields = ["api_key", "password", "token", "secret"]
        decrypted_config = config.copy()

        for key, value in config.items():
            if any(sf in key.lower() for sf in sensitive_fields):
                if isinstance(value, str) and value:
                    try:
                        decrypted_config[key] = self.cipher.decrypt(value.encode()).decode()
                    except Exception:
                        # Value not encrypted or invalid
                        decrypted_config[key] = value

        return decrypted_config

    def _apply_env_overrides(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Apply environment variable overrides."""
        # Map of config keys to environment variables
        env_mappings = {
            "virustotal_api_key": "VIRUSTOTAL_API_KEY",
            "trend_api_key": "TREND_API_KEY",
            "opencti_url": "OPENCTI_URL",
            "opencti_token": "OPENCTI_TOKEN",
            "smtp_username": "SMTP_USERNAME",
            "smtp_password": "SMTP_PASSWORD",
        }

        for config_key, env_var in env_mappings.items():
            if env_var in os.environ:
                config[config_key] = os.getenv(env_var)
                logger.debug("config_override_from_env", key=config_key)

        return config

    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration."""
        return {
            "identity_name": "AntiFraudAgent",
            "identity_class": "system",
            "llm_backend": "local",
            "model_path": "/models/llama-2-7b.gguf",
            "max_urls_to_crawl": 50,
            "max_iocs_to_enrich": 100,
            "max_concurrent_crawls": 5,
            "crawl_timeout": 30,
            "max_depth": 2,
            "urlhaus_enabled": True,
            "virustotal_enabled": False,
            "virustotal_api_key": "",
            "trend_enabled": False,
            "trend_api_key": "",
            "trend_base_url": "https://api.xdr.trendmicro.com",
            "export_to_trend": False,
            "export_to_opencti": False,
            "opencti_url": "",
            "opencti_token": "",
            "daily_enabled": True,
            "daily_time": "07:00",
            "timezone": "America/Montreal",
            "interval_enabled": False,
            "interval_hours": 6,
            "email_enabled": True,
            "smtp_host": "smtp.gmail.com",
            "smtp_port": 587,
            "smtp_username": "",
            "smtp_password": "",
            "from_address": "",
            "recipient_addresses": [],
            "use_tls": True,
            "mcp_web_search_enabled": False,
            "mcp_code_analysis_enabled": False,
            "mcp_screenshot_enabled": False,
        }
