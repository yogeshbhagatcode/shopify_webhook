"""
shopify_webhook Django application initialization.
"""

from django.apps import AppConfig
from django.conf import settings
from openedx.core.djangoapps.plugins.constants import (
    ProjectType,
    SettingsType,
    PluginSettings,
)


class ShopifyWebhookConfig(AppConfig):
    """
    Configuration for the shopify_webhook Django application.
    """

    name = "shopify_webhook"

    plugin_app = {
        "url_config": {
            "lms.djangoapp": {
                "namespace": "shopify_webhook",
                "regex": "^webhooks/",
                "relative_path": "urls",
            }
        },
        PluginSettings.CONFIG: {
            ProjectType.LMS: {
                SettingsType.COMMON: {
                    PluginSettings.RELATIVE_PATH: "settings.common"
                },
                SettingsType.PRODUCTION: {
                    PluginSettings.RELATIVE_PATH: "settings.production"
                },
            },
        },
    }
