from django.contrib import admin

from .models import ShopifyOrder, ShopifyOrderItem, JSONWebhookData


class ShopifyOrderAdmin(admin.ModelAdmin):
    list_display = ["id", "email", "webhook", "status"]
    list_filter = ['status']


class ShopifyOrderItemAdmin(admin.ModelAdmin):
    list_display = ["id", "email", "sku", "order", "status"]
    list_filter = ['status']


class JSONWebhookDataAdmin(admin.ModelAdmin):
    list_display = ["id", "status", "source", "received"]
    list_filter = ['status']


admin.site.register(ShopifyOrder, ShopifyOrderAdmin)
admin.site.register(ShopifyOrderItem, ShopifyOrderItemAdmin)
admin.site.register(JSONWebhookData, JSONWebhookDataAdmin)
