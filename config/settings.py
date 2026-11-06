import os
import re
import yaml
from pathlib import Path
from dotenv import load_dotenv
from src.utils.logger import logger

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_YAML_PATH = BASE_DIR / 'config' / 'config.yaml'

try:
    with open(CONFIG_YAML_PATH) as f:
        config = yaml.safe_load(f)
except FileNotFoundError:
    logger.error(f"Configuration file not found at {CONFIG_YAML_PATH}")
    config = {'models': {}, 'rabbitmq': {}, 'esbmc': {}, 'database': {}, 'queues': {}, 'docker_images': {}, 'sampling_params': {}, 'resource_management': {}}
except yaml.YAMLError as e:
    logger.error(f"Error parsing configuration file {CONFIG_YAML_PATH}: {e}")
    config = {'models': {}, 'rabbitmq': {}, 'esbmc': {}, 'database': {}, 'queues': {}, 'docker_images': {}, 'sampling_params': {}, 'resource_management': {}}

class Settings:
    def __init__(self):
        self.rabbitmq = config.get('rabbitmq', {})
        self.esbmc = config.get('esbmc', {})
        self.docker_images = config.get('docker_images', {})
        self.database = config.get('database', {})
        self.queues = config.get('queues', {})
        self.sampling_params = config.get('sampling_params', {})
        self.resource_management = config.get('resource_management', {})
        self.pairing = config.get('pairing', {})
        # Languages that are never generated (ESBMC cannot verify them), lower-case.
        self.skip_languages = {str(l).lower() for l in (config.get('skip_languages') or [])}
        self.guards = config.get('guards', {})

        self.models = {}
        for name, model_data in config.get('models', {}).items():
            provider = model_data.get('provider')
            enabled = model_data.get('enabled', True)
            model_name = model_data.get('model_name')
            client_config = {}
            
            if not provider or not model_name:
                logger.warning(f"Skipping model '{name}' due to missing 'provider' or 'model_name' in config.yaml")
                continue

            try:
                if provider in ['vllm', 'openai', 'deepseek']:
                    _raw_key = model_data.get('api_key') or os.getenv(f"{name.upper()}_API_KEY")
                    _raw_base = model_data.get('api_base') or os.getenv(f"{name.upper()}_API_BASE")
                    # If the value is an env var name (ALL_CAPS_WITH_UNDERSCORES), resolve it
                    api_key = (os.getenv(_raw_key) or _raw_key) if (_raw_key and re.match(r'^[A-Z][A-Z0-9_]+$', _raw_key)) else _raw_key
                    base_url = (os.getenv(_raw_base) or _raw_base) if (_raw_base and re.match(r'^[A-Z][A-Z0-9_]+$', _raw_base)) else _raw_base
                    if not api_key or not base_url:
                        logger.error(
                            f"Model '{name}' (provider: {provider}) is missing required "
                            f"'api_key' or 'api_base'. Skipping this model."
                        )
                        continue
                    client_config = {'api_key': api_key, 'base_url': base_url}

                elif provider == "azureinference":
                    endpoint = os.getenv("AZURE_AI_INFERENCE_ENDPOINT")
                    api_key = os.getenv("AZURE_AI_INFERENCE_API_KEY")
                    if not endpoint or not api_key:
                        logger.error(
                            f"Model '{name}' (provider: {provider}) is missing "
                            f"AZURE_AI_INFERENCE_ENDPOINT or AZURE_AI_INFERENCE_API_KEY. Skipping."
                        )
                        continue
                    client_config = {'endpoint': endpoint, 'api_key': api_key}

                elif provider == "azureopenai":
                    api_key = os.getenv("AZURE_OPENAI_API_KEY")
                    api_version = os.getenv("AZURE_OPENAI_API_VERSION")
                    azure_endpoint = os.getenv("AZURE_OPENAI_ENDPOINT")
                    if not api_key or not api_version or not azure_endpoint:
                        logger.error(
                            f"Model '{name}' (provider: {provider}) is missing one or more "
                            f"Azure OpenAI environment variables. Skipping."
                        )
                        continue
                    client_config = {
                        'api_key': api_key,
                        'api_version': api_version,
                        'azure_endpoint': azure_endpoint,
                        'azure_deployment': model_name,
                    }
                else:
                    logger.warning(f"Unsupported provider '{provider}' for model '{name}'. Skipping.")
                    continue

                # Queue names are derived from the config key via make_queue_name().
                # Validate that the key is already in normalised form so that the
                # key itself can be stored in the DB as generation_model and later
                # used to reconstruct the correct queue name without ambiguity.
                expected_key = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", model_name)
                if name != expected_key:
                    logger.warning(
                        f"Model key '{name}' does not match the expected key '{expected_key}' "
                        f"(derived from model_name '{model_name}'). "
                        f"Queue names and generation_model values are built from the config "
                        f"key, which is consistent on both sides; this only matters if a "
                        f"tool derives the key from model_name."
                    )

                self.models[name] = {
                    'provider': provider,
                    'model_name': model_name,
                    'client_config': client_config,
                    'enabled': enabled,
                    'max_tokens': model_data.get('max_tokens'),
                    'context_length': model_data.get('context_length'),
                    'extra_body': model_data.get('extra_body'),
                    'max_concurrent_requests': model_data.get('max_concurrent_requests'),
                }

            except Exception as e:
                logger.error(f"Failed to process configuration for model '{name}': {str(e)}")

settings = Settings()
