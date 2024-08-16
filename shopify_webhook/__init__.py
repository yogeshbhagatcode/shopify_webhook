

__version__ = '0.1.0'

default_app_config = 'shopify_webhook.apps.ShopifyWebhookConfig'


class STATE:
    NEW = 0
    PROCESSING = 1
    PROCESSED = 2
    ERROR = -1

    CHOICES = (
        (NEW, 'New'),
        (PROCESSING, 'Processing'),
        (PROCESSED, 'Processed'),
        (ERROR, 'Error'),
    )