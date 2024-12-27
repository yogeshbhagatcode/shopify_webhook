"""
Management command to regenerate unverified certificates when a course
transitions to honor code.
"""
import logging
from django.core.management.base import BaseCommand
from shopify_webhook.models import ShopifyOrder, JSONWebhookData
from shopify_webhook.tasks import process
logger = logging.getLogger(__name__)


class Command(BaseCommand):
    """
    Management command to process failed orders.
    """

    def handle(self, *args, **options):
        # Process all the webhook data which are in ERROR state
        failed_webhooks = JSONWebhookData.objects.filter(status=JSONWebhookData.ERROR)
        for failed_webhook in failed_webhooks:
            try:
                data = failed_webhook
                process.delay(data.content, retrying_order=True)
            except Exception as e:
                logger.info("Unable to process failed webhook data: %s" % e)

        # Process all the order data which are in ERROR state
        failed_orders = ShopifyOrder.objects.filter(status=ShopifyOrder.ERROR)
        for failed_order in failed_orders:
            try:
                webhook_data = failed_order.webhook
                data = JSONWebhookData.objects.get(id=webhook_data.id)
                process.delay(data.content, retrying_order=True)
            except Exception as e:
                logger.info("Unable to process failed order data: %s" % e)
