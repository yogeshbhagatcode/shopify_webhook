from __future__ import unicode_literals
import base64
import hashlib
import hmac
import json
import logging
import re
import requests
from urllib.parse import urlparse

from django.core.validators import validate_email
from django.conf import settings
from django.db import transaction

from edx_rest_api_client.client import OAuthAPIClient
from ipware import get_client_ip

from .models import ShopifyOrder as Order
from .models import ShopifyOrderItem as OrderItem
from .models import JSONWebhookData


EDX_BULK_ENROLLMENT_API_PATH = '%s/api/bulk_enroll/v1/bulk_enroll'

logger = logging.getLogger(__name__)


class SKULookupException(Exception):
    pass


def receive_json_webhook(request):
    # Grab data from the request, and save it to the database right
    # away.
    data = JSONWebhookData(headers=dict(request.headers),
                           body=request.body)
    with transaction.atomic():
        data.save()

    # Transition the state from NEW to PROCESSING
    data.start_processing()
    with transaction.atomic():
        data.save()

    # Look up the source IP
    ip, is_routable = get_client_ip(request)
    if ip is None:
        logger.warning("Unable to get client IP for webhook %s" % data.id)
    data.source = ip
    with transaction.atomic():
        data.save()

    # Parse the payload as JSON
    try:
        try:
            data.content = json.loads(data.body)
        except TypeError:
            # Python <3.6 can't call json.loads() on a byte string
            data.content = json.loads(data.body.decode('utf-8'))
    except Exception:
        # For any other exception, set the state to ERROR and then
        # throw the exception up the stack.
        fail_and_save(data)
        raise

    return data


def fail_and_save(data):
    data.fail()
    with transaction.atomic():
        data.save()


def finish_and_save(data):
    data.finish_processing()
    with transaction.atomic():
        data.save()


def get_hmac(key, body):
    digest = hmac.new(key.encode('utf-8'),
                      body,
                      hashlib.sha256).digest()
    return base64.b64encode(digest).decode()


def hmac_is_valid(key, body, hmac_to_verify):
    return get_hmac(key, body) == hmac_to_verify


def lookup_course_id(sku):
    """Look up the course ID for a SKU"""
    course_id_regex = 'course-v1:[^/]+'

    # If the SKU we're given matches the regex from the beginning of
    # its string, great. It looks like a course ID, use it verbatim.
    if re.match(course_id_regex, sku):
        return sku

    # OK, the SKU does not look like a course ID. So, expect to be
    # able to look up the actual course ID via an HTTP redirect.
    lookup_url = '%s/%s%s' % (settings.WEBHOOK_RECEIVER_LMS_BASE_URL,
                              settings.WEBHOOK_RECEIVER_SKU_PREFIX,
                              sku)
    logger.debug('Resolving SKU %s by looking up %s.' % (sku, lookup_url))
    resp = requests.head(lookup_url,
                         allow_redirects=True)
    resp.raise_for_status()

    # The redirect could point to anywhere in the course: the course
    # URL, the course /about page, the course /course page. Thus,
    # extract the path from the redirect URL, and match it against the
    # pattern. That way, we'll catch anything from the marker
    # "course-v1" up to and excluding the next slash, if there is one.
    logger.debug('Resolving SKU %s returned URL %s.' % (sku, resp.url))
    path = urlparse(resp.url).path
    matches = re.findall(course_id_regex,
                         path)

    # We've found a match, great. Evidently this redirect helped us to
    # resolve a correct course ID. Return it.
    if matches:
        course_id = matches[0]
        logger.debug('Resolving SKU %s returned '
                     'course ID %s.' % (sku, course_id))
        return course_id

    # We haven't found a match, so we can't resolve to a proper course
    # ID.
    raise SKULookupException('Unable to find a course ID '
                             'matching SKU %s' % sku)


def enroll_in_course(
        course_id,
        email,
        send_email=settings.WEBHOOK_RECEIVER_SEND_ENROLLMENT_EMAIL,
        auto_enroll=settings.WEBHOOK_RECEIVER_AUTO_ENROLL
):
    """
    Auto-enroll email in course.

    Uses the bulk enrollment API, defined in lms/djangoapps/bulk_enroll
    """

    # Raises ValidationError if invalid
    validate_email(email)

    client = OAuthAPIClient(
        settings.WEBHOOK_RECEIVER_LMS_BASE_URL,
        settings.WEBHOOK_RECEIVER_EDX_OAUTH2_KEY,
        settings.WEBHOOK_RECEIVER_EDX_OAUTH2_SECRET,
    )


    bulk_enroll_url = EDX_BULK_ENROLLMENT_API_PATH % settings.WEBHOOK_RECEIVER_LMS_BASE_URL  # noqa: E501

    # The bulk enrollment API allows us to enroll multiple identifiers
    # at once, using a comma-separated list for the courses and
    # identifiers parameters. We deliberately want to process
    # enrollments one by one, so we use a single request for each
    # course/identifier combination.
    request_params = {
        "auto_enroll": auto_enroll,
        "email_students": send_email,
        "action": "enroll",
        "courses": course_id,
        "identifiers": email,
    }

    logger.debug("Sending POST request "
                 "to %s with parameters %s" % (bulk_enroll_url,
                                               request_params))
    response = client.post(
        bulk_enroll_url,
        request_params
    )

    # Throw an exception if we get any error back from the API.
    # Apart from an HTTP 200, we might also get:
    #
    # HTTP 400: if we've sent a malformed request (for example, one
    #           with a course ID in a format that Open edX can't
    #           parse)
    # HTTP 401: if our authentication token has expired
    # HTTP 403: if our auth token is linked to a user ID that lacks
    #           staff credentials in one of the courses we want to
    #           enroll the learner in
    # HTTP 404: if we've specified a course ID that does not exist
    #           (although it does follow the format that Open edX expects)
    # HTTP 500: in case of a server-side issue
    if response.status_code >= 400:
        logger.error("POST request to %s with parameters %s "
                     "returned HTTP %s" % (bulk_enroll_url,
                                           request_params,
                                           response.status_code))
    response.raise_for_status()

    # If all is well, log the response at the debug level.
    logger.debug("Received response from %s: %s " % (bulk_enroll_url,
                                                     response.json()))


def record_order(data):
    return Order.objects.get_or_create(
        id=data.content['id'],
        defaults={
            'webhook': data,
            'email': data.content['customer']['email'],
            'first_name': data.content['customer']['first_name'],
            'last_name': data.content['customer']['last_name']
        }
    )


def process_order(order, data, send_email=False):
    if order.status == Order.PROCESSED:
        logger.warning('Order %s has already '
                       'been processed, ignoring' % order.id)
        return
    elif order.status == Order.ERROR:
        logger.warning('Order %s has previously '
                       'failed to process, ignoring' % order.id)
        return

    if order.status == Order.PROCESSING:
        logger.warning('Order %s is already '
                       'being processed, retrying' % order.id)
    else:
        # Start processing the order. A concurrent attempt to access the
        # same order will result in django_fsm.ConcurrentTransition on
        # save(), causing a rollback.
        order.start_processing()
        with transaction.atomic():
            order.save()

    # Process line items
    for item in data['line_items']:
        # Process the line item. If the enrollment throws
        # an exception, we throw that exception up the stack so we can
        # attempt to retry order processing.
        process_line_item(order, item, data['customer'])
        logger.debug('Successfully processed line item '
                     '%s for order %s' % (item, order.id))

    # Mark the order status
    order.finish_processing()
    with transaction.atomic():
        order.save()

    return order


def process_line_item(order, item, customer):
    """Process a line item of an order.

    Extract sku and properties.email, create an OrderItem, create an
    enrollment, and mark the OrderItem as processed. Propagate any
    errors, to be handled up the stack.
    """

    # Fetch relevant fields from the item
    sku = item['sku']
    email = customer['email']

    # Store line item, prop
    order_item, created = OrderItem.objects.get_or_create(
        order=order,
        sku=sku,
        email=email
    )

    if order_item.status == OrderItem.PROCESSED:
        logger.warning('Order item %s has already '
                       'been processed, ignoring' % order_item.id)
        return
    elif order_item.status == OrderItem.PROCESSING:
        logger.warning('Order item %s is already '
                       'being processed, retrying' % order_item.id)
    else:
        order_item.start_processing()
        with transaction.atomic():
            order_item.save()

    # Create an enrollment for the line item. If the enrollment throws
    # an exception, we throw that exception up the stack so we can
    # attempt to retry order processing.
    course_id = lookup_course_id(sku)
    enroll_in_course(course_id, email)

    # Mark the item as processed
    order_item.finish_processing()
    with transaction.atomic():
        order_item.save()

    return order_item
