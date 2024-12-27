from django.urls import re_path
from .views import order_create, order_cancel


urlpatterns = [
    re_path(r"^shopify/order/create$", order_create, name="shopify_order_create"),
    re_path(r"^shopify/order/cancel$", order_cancel, name="shopify_order_cancel")
]
