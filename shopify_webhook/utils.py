from __future__ import unicode_literals
import base64
import hashlib
import hmac
import json
import logging
import re
import requests
from urllib.parse import urlparse
from datetime import datetime

from django.core.validators import validate_email
from django.conf import settings
from django.db import transaction

from edx_rest_api_client.client import OAuthAPIClient
from ipware import get_client_ip

from .models import ShopifyOrder as Order
from .models import ShopifyOrderItem as OrderItem
from .models import JSONWebhookData

from openedx.core.djangoapps.enrollments.api import update_enrollment
from common.djangoapps.course_modes.models import CourseMode
from openedx.core.djangoapps.content.course_overviews.models import CourseOverview
from common.djangoapps.student.models.course_enrollment import CourseEnrollmentAllowed
from lms.djangoapps.program_enrollments.api.writing import _ensure_course_exists
from django.contrib.auth.models import User


EDX_BULK_ENROLLMENT_API_PATH = "%s/api/bulk_enroll/v1/bulk_enroll"

logger = logging.getLogger(__name__)


def receive_json_webhook(request):
    # Grab data from the request, and save it to the database right
    # away.
    data = JSONWebhookData(headers=dict(request.headers), body=request.body)
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
            data.content = json.loads(data.body.decode("utf-8"))
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
    digest = hmac.new(key.encode("utf-8"), body, hashlib.sha256).digest()
    return base64.b64encode(digest).decode()


def hmac_is_valid(key, body, hmac_to_verify):
    return get_hmac(key, body) == hmac_to_verify


def lookup_course_id(sku):
    """Look up the course ID for a SKU"""
    course_id_regex = "course-v1:[^/]+"

    if not sku:
        logger.error(
            "No course id found. Please set correct 'course id' as 'sku'. "
            "Ignore this if this was for subscription purchase."
        )
        return None

    # If the SKU we're given matches the regex from the beginning of
    # its string, great. It looks like a course ID, use it verbatim.
    elif re.match(course_id_regex, sku):
        try:
            _ensure_course_exists(sku, user_key_or_id=None)
            return sku
        except Exception as e:
            logger.error(
                "Course key:%s does not exist. Please set correct 'course id' as 'sku'."
                % sku
            )
            return None
    else:
        logger.error(
            "Course key:%s is not in valid format. Please set correct 'course id' as 'sku'."
            % sku
        )
        return None


def enroll_in_course(
    course_id,
    email,
    mode=None,
    send_email=settings.WEBHOOK_RECEIVER_SEND_ENROLLMENT_EMAIL,
    auto_enroll=settings.WEBHOOK_RECEIVER_AUTO_ENROLL,
    action='enroll'
):
    """
    Auto-enroll email in course.

    Uses the bulk enrollment API, defined in lms/djangoapps/bulk_enroll
    """

    # Raises ValidationError if invalid
    validate_email(email)

    client = OAuthAPIClient(
        settings.LMS_ROOT_URL,
        settings.WEBHOOK_RECEIVER_EDX_OAUTH2_KEY,
        settings.WEBHOOK_RECEIVER_EDX_OAUTH2_SECRET,
    )

    bulk_enroll_url = EDX_BULK_ENROLLMENT_API_PATH % settings.LMS_ROOT_URL  # noqa: E501

    # The bulk enrollment API allows us to enroll multiple identifiers
    # at once, using a comma-separated list for the courses and
    # identifiers parameters. We deliberately want to process
    # enrollments one by one, so we use a single request for each
    # course/identifier combination.
    request_params = {
        "auto_enroll": auto_enroll,
        "email_students": send_email,
        "action": action,
        "courses": course_id,
        "identifiers": email,
    }

    logger.debug(
        "Sending POST request "
        "to %s with parameters %s" % (bulk_enroll_url, request_params)
    )
    response = client.post(bulk_enroll_url, request_params)

    if response.status_code == 200 and mode:
        update_course_mode_for_enrollment(email, course_id, mode)

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
        logger.error(
            "POST request to %s with parameters %s "
            "returned HTTP %s" % (bulk_enroll_url, request_params, response.status_code)
        )
    response.raise_for_status()

    # If all is well, log the response at the debug level.
    logger.debug("Received response from %s: %s " % (bulk_enroll_url, response.json()))


def update_course_mode_for_enrollment(email, course_id, mode):
    """
    Update the enrollment with the appropriate course_mode received from shopify
    """
    if mode in CourseMode.ALL_MODES:
        mode = get_or_create_course_mode(course_id, mode)
        try:
            # If we receive an email with existing user, then update the existing enrollment.
            username = User.objects.get(email=email)
            update_enrollment(username=username, course_id=course_id, mode=mode)
        except User.DoesNotExist:
            # If user does not exist, then it means that CourseEnrollmentAllowed object was created.
            # So, just get that object and update it with appropriate course_mode.
            course_enrollment_allowed = CourseEnrollmentAllowed.objects.get(
                email=email, course_id=course_id
            )
            course_enrollment_allowed.mode = mode
            course_enrollment_allowed.save()
    else:
        logger.error(
            "Invalid course mode:%s found while updating enrollment for email:%s and course:%s"
            % (mode, email, course_id)
        )


def get_or_create_course_mode(course_id, mode):
    """
    Check and return the correct course_mode
    Create one if it does not exist already
    """
    course = CourseOverview.objects.get(id=course_id)
    mode, created = CourseMode.objects.get_or_create(
        course=course, mode_slug=mode, mode_display_name=mode
    )
    return mode.mode_slug


def record_order(data):
    return Order.objects.get_or_create(
        id=data.content["id"],
        defaults={
            "webhook": data,
            "email": data.content["customer"]["email"],
            "first_name": data.content["customer"]["first_name"],
            "last_name": data.content["customer"]["last_name"],
        },
    )


def record_cancellation_order(data):
    customer_id = data.content.get("customerId")
    email = get_shopify_customer_email_from_customer_id(customer_id)
    iso_string = str(data.content.get("occurredAt"))
    dt = datetime.fromisoformat(iso_string.replace("Z", "+00:00"))
    timestamp = int(dt.timestamp() * 1000)  # Convert to milliseconds
    data.content["id"] = timestamp
    data.content["email"] = email
    data.content["subscription_cancellation"] = True
    course_ids = get_shopify_customer_order_product_skus(customer_id)
    data.content["line_items"] = []
    for idx, course_id in enumerate(course_ids, start=1):
        line_item = {
            "id": idx,
            "sku": course_id,
            "variant_title": ""
        }
        data.content["line_items"].append(line_item)

    return Order.objects.get_or_create(
        id=data.content["id"],
        defaults={
            "webhook": data,
            "email": data.content["email"],
        },
    )


def process_order(order, data, retrying_order=False):
    if order.status == Order.PROCESSED:
        logger.warning("Order %s has already been processed, ignoring" % order.id)
        return
    elif order.status == Order.ERROR:
        if retrying_order:
            # Set the status for failed order when called from process_failed_orders management command
            order.set_new()
        else:
            logger.warning(
                "Order %s has previously failed to process, ignoring" % order.id
            )
            return

    if order.status == Order.PROCESSING:
        logger.warning("Order %s is already being processed, retrying" % order.id)
    else:
        # Start processing the order. A concurrent attempt to access the
        # same order will result in django_fsm.ConcurrentTransition on
        # save(), causing a rollback.
        order.start_processing()
        with transaction.atomic():
            order.save()

    subscription_cancellation = data.get("subscription_cancellation")

    # Process line items
    for item in data["line_items"]:
        # Process the line item. If the enrollment throws
        # an exception, we throw that exception up the stack so we can
        # attempt to retry order processing.
        process_line_item(order, item, subscription_cancellation=subscription_cancellation)
        logger.debug(
            "Successfully processed line item %s for order %s" % (item, order.id)
        )

    # Mark the order status
    order.finish_processing()
    with transaction.atomic():
        order.save()

    if retrying_order:
        # Update status of Webhook data when called from process_failed_orders management command.
        webhook_data = order.webhook
        if webhook_data.status != JSONWebhookData.PROCESSED:
            webhook_data.set_finish()
            webhook_data.save()

    return order


def process_line_item(order, item, subscription_cancellation=False):
    """Process a line item of an order.

    Extract sku and properties.email, create an OrderItem, create an
    enrollment, and mark the OrderItem as processed. Propagate any
    errors, to be handled up the stack.
    """

    # Fetch relevant fields from the item
    sku = item.get("sku")
    mode = item.get("variant_title")
    email = order.email

    # Store line item, prop
    order_item, created = OrderItem.objects.get_or_create(
        order=order, sku=sku, email=email
    )

    if order_item.status == OrderItem.PROCESSED:
        logger.warning(
            "Order item %s has already been processed, ignoring" % order_item.id
        )
        return
    elif order_item.status == OrderItem.PROCESSING:
        logger.warning(
            "Order item %s is already being processed, retrying" % order_item.id
        )
    else:
        order_item.start_processing()
        with transaction.atomic():
            order_item.save()

    course_id = lookup_course_id(sku)

    if course_id:
        if subscription_cancellation:
            enroll_in_course(course_id, email, mode, action='unenroll')
        else:
            # Create an enrollment for the line item. If the enrollment throws
            # an exception, we throw that exception up the stack so we can
            # attempt to retry order processing.
            enroll_in_course(course_id, email, mode)

        # Mark the item as processed
        order_item.finish_processing()
        with transaction.atomic():
            order_item.save()

    elif not course_id and subscription_cancellation:
        # Mark the item as processed
        order_item.finish_processing()
        with transaction.atomic():
            order_item.save()

    else:
        # Mark the item as failed
        order_item.fail()
        with transaction.atomic():
            order_item.save()

    return order_item


def get_shopify_customer_email_from_customer_id(customer_id):
    access_token = settings.SHOPIFY_ADMIN_API_ACCESS_TOKEN
    url = settings.SHOPIFY_ADMIN_API_URL

    # GraphQL query
    query = f"""
        query {{
            customer(id: "{customer_id}") {{
                id
                email
            }}
        }}
    """

    headers = {
        'Content-Type': 'application/json',
        'X-Shopify-Access-Token': access_token
    }

    payload = {
        'query': query
    }

    response = requests.post(url, headers=headers, json=payload)

    if response.status_code == 200:
        data = response.json()
        customer_email = data["data"]['customer'].get("email")
        return customer_email
    else:
        logging.error("Error while getting customer email from shopify admin API.")
        logging.error("{response.status_code}: response.text")


def get_shopify_customer_order_product_skus(customer_id):
    access_token = settings.SHOPIFY_ADMIN_API_ACCESS_TOKEN
    url = settings.SHOPIFY_ADMIN_API_URL

    # GraphQL query with customerId as a variable
    query = """
    query getOrders($customerId: ID!, $cursor: String) {
        customer(id: $customerId) {
            orders(first: 250, after: $cursor) {
                edges {
                    node {
                        id
                        createdAt
                        lineItems(first: 250) {
                            edges {
                                node {
                                    title
                                    quantity
                                    variant {
                                        sku
                                    }
                                }
                            }
                        }
                    }
                }
                pageInfo {
                    hasNextPage
                    endCursor
                }
            }
        }
    }
    """

    headers = {
        'Content-Type': 'application/json',
        'X-Shopify-Access-Token': access_token
    }

    skus = set()
    cursor = None

    while True:
        payload = {
            'query': query,
            'variables': {
                'customerId': customer_id,
                'cursor': cursor
            }
        }

        response = requests.post(url, headers=headers, json=payload, timeout=10)
        if response.status_code == 200:
            try:
                data = response.json()

                orders = data['data']['customer']['orders']['edges']

                # Extract SKUs and email from the order line items
                for order in orders:
                    # Safely get 'node' from the order, ensuring it is not None
                    node = order.get('node')
                    if node:
                        line_items = node.get('lineItems', {}).get('edges', [])
                        for item in line_items:
                            # Safely get 'variant' from item, ensuring it is not None
                            variant = item.get('node', {}).get('variant')
                            if variant:
                                sku = variant.get('sku')
                                if sku:
                                    skus.add(sku)

                # Check if there are more orders to fetch
                page_info = data['data']['customer']['orders']['pageInfo']
                if page_info['hasNextPage']:
                    cursor = page_info['endCursor']  # Update cursor for next page
                else:
                    break  # No more pages, exit the loop

            except Exception as e:
                logging.error(f"Error while parsing response: {e}")
                logging.error(f"Response content: {response.text}")
                break
        else:
            logging.error("Error while getting customer orders from Shopify admin API.")
            logging.error(f"{response.status_code}: {response.text}")
            break

    return list(skus)
