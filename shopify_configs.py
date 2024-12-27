from tutor import hooks

hooks.Filters.ENV_PATCHES.add_item(
    (
        "lms-env-features",
        """
"ENABLE_BULK_ENROLLMENT_VIEW": true
"""
    )
)


hooks.Filters.ENV_PATCHES.add_items([
    ("openedx-lms-common-settings", """
WEBHOOK_RECEIVER_EDX_OAUTH2_KEY = "replace-value-here"
WEBHOOK_RECEIVER_EDX_OAUTH2_SECRET = "replace-value-here"
WEBHOOK_RECEIVER_SEND_ENROLLMENT_EMAIL = True
WEBHOOK_RECEIVER_AUTO_ENROLL = True
WEBHOOK_RECEIVER_SETTINGS = {
    'shopify': {
        'shop_domain': 'replace-value-here',
        'api_key': 'replace-value-here',
    }
}
SHOPIFY_ADMIN_API_URL = "replace-value-here"
SHOPIFY_ADMIN_API_ACCESS_TOKEN = "replace-value-here"
    """)
])