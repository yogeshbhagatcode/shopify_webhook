# Shopify Webhook
This is a small Django app that listens for incoming webhooks, and then translates those into calls against the Open edX REST APIs.

It provides the following endpoints:

* `webhooks/shopify/order/create`  
* `webhooks/shopify/order/cancel`  

  These endpoints accept a POST request with JSON
  data, as they would be received by a [Shopify
  webhook](https://help.shopify.com/en/manual/orders/notifications/webhooks)
  firing.

---

## Getting started

### Method 1: (Preferable for Production)

1. **Run the following command to add this plugin as requirement**:
   
   ```
   tutor config save --append OPENEDX_EXTRA_PIP_REQUIREMENTS=git+https://replace-this-url/shopify_webhook.git
   ```
2. **Now build image using**:
   
   ```
   tutor images build openedx --no-cache
   ```

### Method 2: (Preferable for Development)

1. **Clone this repo inside the following directory**:
   
   ```
   $(tutor config printroot)/env/build/openedx/requirements
   ```
2. **Locate the ``private.txt`` file in the same directory and add the following in it**:
   
   ``` yaml
   -e ./shopify_webhook/
   ```
  
3. **Now build image using**:
   
   ```
   tutor images build openedx --no-cache
   ```

---

## To apply the migrations:

1. **Run the following command**:
   
   ```
   tutor local run lms ./manage.py lms makemigrations
   ```

---

## Create OAuth2 Client

1. Go to `{replace-lms-url}/admin/oauth2_provider/application/`  

2. Select **Add application**  

3. **Client id**: webhook_receiver   

4. Select a **User** that has global _Staff_ permissions. 

5. Leave **Redirect uris** blank.

6. For **Client type,** select **Confidential**. 

7. For **Authorization grant type**, select **Client credentials**.  

8. Leave **Client secret** unchanged.

9. For **Name**, enter `webhook_receiver`, or any other client
   name you find appropriate.

10. Leave **Skip authorization** unchecked.

11. Select **Save**.  

---

## Plugin installation
1. Copy the content of ``shopify_configs.py`` file from this repo.  

2. Go to ``$(tutor config printroot)/env/plugins/`` directory and create a file ``shopify_configs.py``.  

3. Now paste the copied content in this file and save it.  

4. Run the following command to enable this plugin:
   ```
   tutor plugins enable shopify_configs
   ```

## Plugin configs
1. WEBHOOK_RECEIVER_EDX_OAUTH2_KEY: `Client id` from `OAuth2 Client` setup
2. WEBHOOK_RECEIVER_EDX_OAUTH2_SECRET: `Client secret` from `OAuth2 Client` setup
3. shop_domain: Your shopify shop domain
4. api_key: Get from `https://admin.shopify.com/store/{your-shop-id}/settings/notifications/webhooks` page
5. SHOPIFY_ADMIN_API_URL: "https://{your-shop-id}.myshopify.com/admin/api/2024-10/graphql.json"
6. SHOPIFY_ADMIN_API_ACCESS_TOKEN: `access token` that was auto-generated while `app` was created in shopify.

---
## Shopify admin API
1. Go to your `Apps and sales channels` page using shopify admin account.
2. Select the app which you are using for `access token` as `SHOPIFY_ADMIN_API_ACCESS_TOKEN`.
3. Click on `Configuration` tab.
4. Click on `edit` button in `Admin API integration` section.
5. In `Admin API access scopes` select these three options:  
   `read_customers`, `read_orders` and `read_products`

---

## Setup on shopify
### Webhook for product purchase:
1. Go to shopify webhook notification setting:  
   ``` yaml
   https://admin.shopify.com/store/{replace-shop-id}/settings/notifications/webhooks 
   ```
 
2. Select **Create webhook**  

3. Select **Order fulfillment** from **Event** dropdown  

4. Set the following as **url**:  
   ``` yaml
   https://{replace-lms-url}/webhooks/shopify/order/create 
   ```

5. Select **2024-10 (Latest)** (Or the latest stable version) from **Webhook API version** dropdown  

6. Click on **Save**.  
##
### Webhook to catch tag removal (subscription cancellation):
1. On shopify webhook notification setting page select **Create webhook**  

3. Select **Customer tags removed** from **Event** dropdown  

4. Set the following as **url**:  
   ``` yaml
   https://{replace-lms-url}/webhooks/shopify/order/cancel 
   ```

5. Select **2024-10 (Latest)** (Or the latest stable version) from **Webhook API version** dropdown  

6. Click on **Save**.  
---

## Product creation on shopify
1. While creating product on shopify, use **course_id** from openedx as **SKU (Stock Keeping Unit)**:  
   For example: 
   `course-v1:Org_name+CS001+2024`
 
2. You can specify the course mode in the product by following these steps:  
   1. In **Variants** section, click on **Add options like size or color**  
   2. Enter **Course mode** as **Option name**
   3. Enter a valid openedx course mode  as **Option values**:  
      For example: `no-id-professional`  
