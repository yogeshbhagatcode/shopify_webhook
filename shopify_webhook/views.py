from __future__ import unicode_literals

import logging

from django.conf import settings
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from .utils import receive_json_webhook, hmac_is_valid
from .utils import fail_and_save, finish_and_save

from .utils import record_order, record_cancellation_order
from .models import Order
from .tasks import process


logger = logging.getLogger(__name__)

def checks(func):
    def inner(request):
        # Load configuration
        conf = settings.WEBHOOK_RECEIVER_SETTINGS["shopify"]

        try:
            data = receive_json_webhook(request)
            request.data = data
        except Exception:
            return HttpResponse(status=400)

        try:
            shop_domain = request.headers["X-Shopify-Shop-Domain"]
        except KeyError:
            logger.error("Request is missing X-Shopify-Shop-Domain header")
            fail_and_save(data)
            return HttpResponse(status=400)

        if not ((conf.get("shop_domains") and shop_domain in conf["shop_domains"]) or (
            conf.get("shop_domain") and shop_domain == conf["shop_domain"])):
            logger.error("Unknown shop domain %s" % shop_domain)
            fail_and_save(data)
            return HttpResponse(status=403)

        try:
            hmac = request.headers["X-Shopify-Hmac-Sha256"]
        except KeyError:
            logger.error("Request is missing X-Shopify-Hmac-Sha256 header")
            fail_and_save(data)
            return HttpResponse(status=400)

        if not hmac_is_valid(conf["api_key"], request.body, hmac):
            logger.error("Failed to verify HMAC signature")
            fail_and_save(data)
            return HttpResponse(status=403)
        return func(request)
    return inner


@csrf_exempt
@require_POST
@checks
def order_create(request):
    data = request.data
    tags = data.content.get("tags")
    subscription_purchase = 'subscription'.lower() in tags.lower()
    if subscription_purchase:
        finish_and_save(data)
        return HttpResponse(status=200)

    finish_and_save(data)

    # Record order
    order, created = record_order(data)
    if created:
        logger.info("Created order %s" % order.id)
    else:
        logger.info("Retrieved order %s" % order.id)

    # Process order
    if order.status == Order.NEW:
        logger.info("Scheduling order %s for processing" % order.id)
        process.delay(data.content)
    else:
        logger.info("Order %s already processed, nothing to do" % order.id)

    return HttpResponse(status=200)


@csrf_exempt
@require_POST
@checks
def order_cancel(request):
    data = request.data
    finish_and_save(data)

    # Record order
    order, created = record_cancellation_order(data)
    if created:
        logger.info("Created cancellation order %s" % order.id)
    else:
        logger.info("Retrieved cancellation order %s" % order.id)
    # Process order
    if order.status == Order.NEW:
        logger.info("Scheduling cancellation order %s for processing" % order.id)
        process.delay(data.content)
    else:
        logger.info("Cancellation order %s already processed, nothing to do" % order.id)

    return HttpResponse(status=200)
