from __future__ import unicode_literals
import frappe
from frappe import _
from .exceptions import woocommerceError
from .utils import make_woocommerce_log
from .sync_customers import create_customer, create_customer_address, create_customer_contact
from frappe.utils import flt, nowdate, cint, add_days
from .woocommerce_requests import get_request, get_woocommerce_orders, get_woocommerce_tax, get_woocommerce_customer, put_request
from erpnext.selling.doctype.sales_order.sales_order import make_delivery_note, make_sales_invoice
import requests.exceptions
import base64, requests, datetime, os
from datetime import datetime


def sync_orders():
    sync_woocommerce_orders()


def sync_woocommerce_orders():
    frappe.local.form_dict.count_dict["orders"] = 0
    woocommerce_settings = frappe.get_doc("WooCommerce Config", "WooCommerce Config")
    woocommerce_order_status_for_import = get_woocommerce_order_status_for_import()
    if not woocommerce_order_status_for_import:
        woocommerce_order_status_for_import = ['processing']
    
    for woocommerce_order_status in woocommerce_order_status_for_import:
        orders = get_woocommerce_orders(woocommerce_order_status)
        # Log the retrieval of orders
        make_woocommerce_log(title=f"Retrieved Orders", status="Success", method="sync_woocommerce_orders",
                             message=f"Retrieved {len(orders)} orders with status '{woocommerce_order_status}'.",
                             request_data={'order_status': woocommerce_order_status}, exception=False)
        
        for woocommerce_order in orders:
            so = frappe.db.get_value("Sales Order", {"woocommerce_order_id": woocommerce_order.get("id")}, "name")
            if not so:
                if valid_customer_and_product(woocommerce_order):
                    try:
                        create_order(woocommerce_order, woocommerce_settings)
                        frappe.local.form_dict.count_dict["orders"] += 1
                        # Log successful order creation
                        make_woocommerce_log(title="Order Synced", status="Success", method="sync_woocommerce_orders",
                                             message=f"Successfully created order {woocommerce_order.get('id')}.",
                                             request_data=woocommerce_order, exception=False)

                    except woocommerceError as e:
                        make_woocommerce_log(status="Error", method="sync_woocommerce_orders", message=frappe.get_traceback(),
                                             request_data=woocommerce_order, exception=True)
                    except Exception as e:
                        if e.args and e.args[0] and e.args[0].startswith("402"):
                            raise e
                        else:
                            make_woocommerce_log(title=str(e), status="Error", method="sync_woocommerce_orders", message=frappe.get_traceback(),
                                                 request_data=woocommerce_order, exception=True)

            if woocommerce_order.get("status").lower() == "processing":
                close_synced_woocommerce_order(woocommerce_order.get("id"))





def get_woocommerce_order_status_for_import():
    status_list = []
    _status_list = frappe.db.sql("""SELECT `status` FROM `tabWooCommerce SO Status`""", as_dict=True)
    for status in _status_list:
        status_list.append(status.status)
    return status_list

def valid_customer_and_product(woocommerce_order):
    order_status = woocommerce_order.get("status").lower()
    if order_status == "cancelled" or order_status != "processing":
        return False
    warehouse = frappe.get_doc("WooCommerce Config", "WooCommerce Config").warehouse
	
    for item in woocommerce_order.get("line_items"):
        if item.get("product_id"):
            if not frappe.db.get_value("Item", {"woocommerce_product_id": item.get("product_id")}, "item_code"):
                make_woocommerce_log(title="Item missing in ERPNext!", status="Error", method="valid_customer_and_product", message="Item with id {0} is missing in ERPNext! The Order {1} will not be imported! For details of order see below".format(item.get("product_id"), woocommerce_order.get("id")),
                    request_data=woocommerce_order, exception=True)
                return False
        else:
            make_woocommerce_log(title="Item id missing in WooCommerce!", status="Error", method="valid_customer_and_product", message="Item id is missing in WooCommerce! The Order {0} will not be imported! For details of order see below".format(woocommerce_order.get("product_id")),
                request_data=woocommerce_order, exception=True)
            return False
    
    try:
        customer_id = int(woocommerce_order.get("customer_id"))
    except:
        customer_id = 0
        
    if customer_id > 0:
        if not frappe.db.get_value("Customer", {"woocommerce_customer_id": str(customer_id)}, "name", False,True):
            woocommerce_customer = get_woocommerce_customer(customer_id)

            #Customer may not have billing and shipping address on file, pull it from the order
            if woocommerce_customer["billing"].get("address_1") == "":
                woocommerce_customer["billing"] = woocommerce_order["billing"]
                woocommerce_customer["billing"]["country"] = get_country_from_code( woocommerce_customer.get("billing").get("country") )

                if woocommerce_customer["shipping"].get("address_1") == "":
                    woocommerce_customer["shipping"] = woocommerce_order["shipping"]
                    woocommerce_customer["shipping"]["country"] = get_country_from_code( woocommerce_customer.get("shipping").get("country") )
            
            create_customer(woocommerce_customer, woocommerce_customer_list=[])

    if customer_id == 0: # we are dealing with a guest customer 

        if not frappe.db.get_value("Customer", {"woocommerce_customer_id": "Guest of Order-ID: {0}".format(woocommerce_order.get("id"))}, "name", False,True):
            make_woocommerce_log(title="create new customer based on guest order", status="Started", method="valid_customer_and_product", message="creat new customer based on guest order",
                request_data=woocommerce_order, exception=False)
            create_new_customer_of_guest(woocommerce_order)

    return True

def get_country_from_code(country_code):
    return frappe.db.get_value("Country", {"code": country_code}, "name")

def create_new_customer_of_guest(woocommerce_order):
    import frappe.utils.nestedset

    woocommerce_settings = frappe.get_doc("WooCommerce Config", "WooCommerce Config")
    
    cust_id = "Guest of Order-ID: {0}".format(woocommerce_order.get("id"))
    cust_info = woocommerce_order.get("billing")
        
    try:
        customer = frappe.get_doc({
            "doctype": "Customer",
            "name": cust_id,
            "customer_name" : "{0} {1}".format(cust_info["first_name"], cust_info["last_name"]),
            "woocommerce_customer_id": cust_id,
            "sync_with_woocommerce": 0,
            "customer_group": woocommerce_settings.customer_group,
            "territory": frappe.utils.nestedset.get_root_of("Territory"),
            "customer_type": _("Individual")
        })
        customer.flags.ignore_mandatory = True
        customer.insert()
        
        if customer:
            create_customer_address(customer, woocommerce_order)
            create_customer_contact(customer, woocommerce_order)
    
        frappe.db.commit()
        frappe.local.form_dict.count_dict["customers"] += 1
        make_woocommerce_log(title="create customer", status="Success", method="create_new_customer_of_guest",
            message= "create customer",request_data=woocommerce_order, exception=False)
    
    except Exception as e:
        if e.args and e.args[0] and e.args[0].startswith("402"):
            raise e
        else:
            make_woocommerce_log(title=str(e), status="Error", method="create_new_customer_of_guest", message=frappe.get_traceback(),
                request_data=woocommerce_order, exception=True)

def get_country_name(code):
    country_name = ''
    if code is None:
        country_name = "Nigeria"
    else:
        country_names = """SELECT `country_name` FROM `tabCountry` WHERE `code` = '{0}'""".format(code.lower())
        for _country_name in frappe.db.sql(country_names, as_dict=1):
            country_name = _country_name.country_name
    return country_name


# def create_sales_order(woocommerce_order, woocommerce_settings, company=None):
     # Only proceed if order status is "processing"
    # if woocommerce_order.get("status").lower() != "processing":
    #     return

    # id = str(woocommerce_order.get("customer_id"))
    # customer = frappe.get_all("Customer", filters=[["woocommerce_customer_id", "=", id]], fields=['name'])
    # backup_customer = frappe.get_all("Customer", filters=[["woocommerce_customer_id", "=", "Guest of Order-ID: {0}".format(woocommerce_order.get("id"))]], fields=['name'])
    # if customer:
    #     customer = customer[0]['name']
    # elif backup_customer:
    #     customer = backup_customer[0]['name']
    # else:
    #     frappe.log_error("No customer found. This should never happen.")

    # so = frappe.db.get_value("Sales Order", {"woocommerce_order_id": woocommerce_order.get("id")}, "name")
    # if not so:
    #     # get shipping/billing address
    #     shipping_address = get_customer_address_from_order('Shipping', woocommerce_order, customer)
    #     billing_address = get_customer_address_from_order('Billing', woocommerce_order, customer)

    #     # get applicable tax rule from configuration
    #     tax_rules = frappe.get_all("WooCommerce Tax Rule", filters={'currency': woocommerce_order.get("currency")}, fields=['tax_rule'])
    #     if not tax_rules:
    #         # fallback: currency has no tax rule, try catch-all
    #         tax_rules = frappe.get_all("WooCommerce Tax Rule", filters={'currency': "%"}, fields=['tax_rule'])
    #     if tax_rules:
    #         tax_rules = tax_rules[0]['tax_rule']
    #     else:
    #         tax_rules = ""
    #     so = frappe.get_doc({
    #         "doctype": "Sales Order",
    #         "naming_series": woocommerce_settings.sales_order_series or "SO-woocommerce-",
    #         "woocommerce_order_id": woocommerce_order.get("id"),
    #         "woocommerce_payment_method": woocommerce_order.get("payment_method_title"),
    #         "customer": customer,
    #         "customer_group": woocommerce_settings.customer_group,  # hard code group, as this was missing since v12
    #         "delivery_date": nowdate(),
    #         "company": woocommerce_settings.company,
    #         "selling_price_list": woocommerce_settings.price_list,
    #         "ignore_pricing_rule": 1,
    #         "items": get_order_items(woocommerce_order.get("line_items"), woocommerce_settings),
    #         "taxes": get_order_taxes(woocommerce_order, woocommerce_settings),
    #         # disabled discount as WooCommerce will send this both in the item rate and as discount
    #         #"apply_discount_on": "Net Total",
    #         #"discount_amount": flt(woocommerce_order.get("discount_total") or 0),
    #         "currency": woocommerce_order.get("currency"),
    #         "taxes_and_charges": tax_rules,
    #         "customer_address": billing_address,
    #         "shipping_address_name": shipping_address,
    #         "posting_date": woocommerce_order.get("date_created")[:10]        # pull posting date from WooCommerce
    #     })

    #     so.flags.ignore_mandatory = True

    #     # alle orders in ERP = submitted
    #     so.save(ignore_permissions=True)
    #     so.submit()
    #     #if woocommerce_order.get("status") == "on-hold":
    #     #    so.save(ignore_permissions=True)
    #     #elif woocommerce_order.get("status") in ("cancelled", "refunded", "failed"):
    #     #    so.save(ignore_permissions=True)
    #     #    so.submit()
    #     #    so.cancel()
    #     #else:
    #     #    so.save(ignore_permissions=True)
    #     #    so.submit()

    # else:
    #     so = frappe.get_doc("Sales Order", so)

    # frappe.db.commit()
    # make_woocommerce_log(
    #     title=str(e),
    #     status="Error",
    #     method="create_customer",
    #     message="create sales_order",
    #     request_data=woocommerce_order,
    #     exception=False
    # )
    # return so

def create_order(woocommerce_order, woocommerce_settings, company=None):
    # Only proceed if order status is "processing"
    if woocommerce_order.get("status").lower() != "processing":
        return

    try:
        so = create_sales_order(woocommerce_order, woocommerce_settings, company)
    except Exception as e:
        make_woocommerce_log(
            title=str(e),
            status="Error",
            method="create_order",
            message="Error while creating sales order",
            request_data=woocommerce_order,
            exception=True
        )
        return

    # check if sales invoice should be created
    if cint(woocommerce_settings.sync_sales_invoice) == 1:
        create_sales_invoice(woocommerce_order, woocommerce_settings, so)

    #Fix this -- add shipping stuff
    #if woocommerce_order.get("fulfillments") and cint(woocommerce_settings.sync_delivery_note):
        #create_delivery_note(woocommerce_order, woocommerce_settings, so)
    return so

# def create_sales_order(woocommerce_order, woocommerce_settings, company=None):
#     # Only proceed if order status is "processing"
#     if woocommerce_order.get("status").lower() != "processing":
#         return

#     id = str(woocommerce_order.get("customer_id"))
#     customer = frappe.get_all("Customer", filters=[["woocommerce_customer_id", "=", id]], fields=['name'])
#     backup_customer = frappe.get_all("Customer", filters=[["woocommerce_customer_id", "=", "Guest of Order-ID: {0}".format(woocommerce_order.get("id"))]], fields=['name'])
#     if customer:
#         customer = customer[0]['name']
#     elif backup_customer:
#         customer = backup_customer[0]['name']
#     else:
#         frappe.log_error("No customer found. This should never happen.")

#     so = frappe.db.get_value("Sales Order", {"woocommerce_order_id": woocommerce_order.get("id")}, "name")
#     if not so:
#         # get shipping/billing address
#         shipping_address = get_customer_address_from_order('Shipping', woocommerce_order, customer)
#         billing_address = get_customer_address_from_order('Billing', woocommerce_order, customer)

#         # get applicable tax rule from configuration
#         tax_rules = frappe.get_all("WooCommerce Tax Rule", filters={'currency': woocommerce_order.get("currency")}, fields=['tax_rule'])
#         if not tax_rules:
#             # fallback: currency has no tax rule, try catch-all
#             tax_rules = frappe.get_all("WooCommerce Tax Rule", filters={'currency': "%"}, fields=['tax_rule'])
#         if tax_rules:
#             tax_rules = tax_rules[0]['tax_rule']
#         else:
#             tax_rules = ""
        
#         date_created = woocommerce_order.get("date_created")
#         # Parse the date and time from the string, then format the date part as 'YYYY-MM-DD'
#         date_created = datetime.strptime(date_created, '%Y-%m-%dT%H:%M:%S').strftime('%Y-%m-%d')
#         so = frappe.get_doc({
#             "doctype": "Sales Order",
#             "naming_series": woocommerce_settings.sales_order_series or "SO-woocommerce-",
#             "woocommerce_order_id": woocommerce_order.get("id"),
#             "woocommerce_payment_method": woocommerce_order.get("payment_method_title"),
#             "customer": customer,
#             "customer_group": woocommerce_settings.customer_group,  # hard code group, as this was missing since v12
#             "delivery_date": date_created,
#             "company": woocommerce_settings.company,
#             "selling_price_list": woocommerce_settings.price_list,
#             "ignore_pricing_rule": 1,
#             "items": get_order_items(woocommerce_order.get("line_items"), woocommerce_settings),
#             "taxes": get_order_taxes(woocommerce_order, woocommerce_settings),
#             #"apply_discount_on": "Net Total",
#             #"discount_amount": flt(woocommerce_order.get("discount_total") or 0),
#             "currency": woocommerce_order.get("currency"),
#             "taxes_and_charges": tax_rules,
#             "customer_address": billing_address,
#             "shipping_address_name": shipping_address,
#             "transaction_date": date_created
#         })

#         so.append('payment_schedule', {
#             'due_date': date_created,
#             'invoice_portion': 100.0,
#             'payment_amount': flt(woocommerce_order.get("total")),
#         })

#         so.flags.ignore_mandatory = True

#         # alle orders in ERP = submitted
#         so.save(ignore_permissions=True)
#         so.submit()



def create_sales_order(woocommerce_order, woocommerce_settings, company=None):
    try:
        make_woocommerce_log(title="Sales Order Process Initiated", status="Started", method="create_sales_order", 
                             message="Starting the sales order creation process.", request_data=woocommerce_order, exception=False)
        
        if not isinstance(woocommerce_order, dict):
            raise ValueError("woocommerce_order is not a dictionary")

        if woocommerce_order.get("status").lower() != "processing":
            raise ValueError(f"Order status {woocommerce_order.get('status')} is not 'processing'.")

        customer_name = get_customer_name(woocommerce_order.get("customer_id"), woocommerce_order)
        order_total = flt(woocommerce_order.get("total", 0))
        date_created = validate_and_format_date(woocommerce_order.get("date_created", ""))
        
        # Get taxes from the order
        taxes = get_order_taxes(woocommerce_order, woocommerce_settings)

        so_doc = prepare_sales_order_doc(woocommerce_order, woocommerce_settings, customer_name, date_created, order_total, taxes)

        so = frappe.get_doc(so_doc)
        so.flags.ignore_mandatory = True
        so.save(ignore_permissions=True)

        so.submit()
        
        make_woocommerce_log(title="Sales Order Submitted", status="Success", method="create_sales_order",
                             message=f"Sales order {so.name} submitted successfully.", request_data={"so_name": so.name}, exception=False)

        return {"status": "Success", "message": f"Sales Order {so.name} successfully created."}
    except Exception as e:
        make_woocommerce_log(title="Sales Order Creation Failed", status="Error", method="create_sales_order",
                             message=str(e), request_data=woocommerce_order, exception=True)
        return {"status": "Error", "message": str(e)}



def get_customer_name(customer_id, woocommerce_order):
    customer = frappe.get_all("Customer", filters=[["woocommerce_customer_id", "=", customer_id]], fields=['name'])
    backup_customer = frappe.get_all("Customer", filters=[["woocommerce_customer_id", "=", f"Guest of Order-ID: {woocommerce_order.get('id')}"]], fields=['name'])
    if customer:
        return customer[0]['name']
    elif backup_customer:
        return backup_customer[0]['name']
    else:
        raise ValueError("No customer found for order.")

def validate_and_format_date(date_str):
    if not date_str:
        raise ValueError("Date created is missing.")
    return datetime.strptime(date_str, '%Y-%m-%dT%H:%M:%S').strftime('%Y-%m-%d')


def prepare_sales_order_doc(woocommerce_order, woocommerce_settings, customer_name, date_created, order_total, taxes):
    items = []
    for line_item in woocommerce_order.get("line_items", []):
        item_code = map_woocommerce_product_to_erp_item(line_item.get("product_id"))
        items.append({
            "item_code": item_code,
            "qty": line_item.get("quantity"),
            "rate": line_item.get("price"), 
        })
    
    return {
        "doctype": "Sales Order",
        "naming_series": woocommerce_settings.sales_order_series or "SO-woocommerce-",
        "woocommerce_order_id": woocommerce_order.get("id"),
        "woocommerce_payment_method": woocommerce_order.get("payment_method_title"),
        "customer": customer_name,
        "delivery_date": date_created,
        "company": woocommerce_settings.company,
        "selling_price_list": woocommerce_settings.price_list,
        "ignore_pricing_rule": 1,
        "items": items,
        "taxes": taxes,
        "currency": woocommerce_order.get("currency"),
        "payment_schedule": [{
            'due_date': date_created,
            'invoice_portion': 100,
            'payment_amount': order_total,
        }]
    }



def map_woocommerce_product_to_erp_item(product_id):
    item_code = frappe.db.get_value('Item', {'woocommerce_product_id': str(product_id)}, 'name')
    if item_code:
        return item_code
    else:
        make_woocommerce_log(title="Item Mapping Failed", status="Error", method="create_sales_order",
                             message=f"No ERPNext item found for WooCommerce product ID {product_id}", request_data={'product_id': product_id}, exception=True)
        return None




def get_customer_address_from_order(type, woocommerce_order, customer):
    address_record = woocommerce_order[type.lower()]
    address_name = frappe.db.get_value("Address", {"woocommerce_address_id": type, "address_line1": address_record.get("address_1"), "woocommerce_company_name": address_record.get("company") or ''}, "name")
    if not address_name:
        country = get_country_name(address_record.get("country"))
        if not frappe.db.exists("Country", country):
            country = "Switzerland"
        try :
            address_name = frappe.get_doc({
                "doctype": "Address",
                "woocommerce_address_id": type,
                "woocommerce_company_name": address_record.get("company") or '',
                "address_title": customer,
                "address_type": type,
                "address_line1": address_record.get("address_1") or "Address 1",
                "address_line2": address_record.get("address_2"),
                "city": address_record.get("city") or "City",
                "state": address_record.get("state"),
                "pincode": address_record.get("postcode"),
                "country": country,
                "phone": address_record.get("phone"),
                "email_id": address_record.get("email"),
                "links": [{
                    "link_doctype": "Customer",
                    "link_name": customer
                }]
            }).insert()
            address_name = address_name.name

        except Exception as e:
            make_woocommerce_log(title=e, status="Error", method="create_customer_address", message=frappe.get_traceback(),
                    request_data=address_name, exception=True)

    return address_name

def create_sales_invoice(woocommerce_order, woocommerce_settings, so):
    if not frappe.db.get_value("Sales Invoice", {"woocommerce_order_id": woocommerce_order.get("id")}, "name")\
        and so.docstatus==1 and not so.per_billed:
        si = make_sales_invoice(so.name)
        si.woocommerce_order_id = woocommerce_order.get("id")
        si.naming_series = woocommerce_settings.sales_invoice_series or "SI-woocommerce-"
        si.flags.ignore_mandatory = True
        set_cost_center(si.items, woocommerce_settings.cost_center)
        si.submit()
        if cint(woocommerce_settings.import_payment) == 1:
            make_payment_entry_against_sales_invoice(si, woocommerce_settings)
        frappe.db.commit()

def set_cost_center(items, cost_center):
    for item in items:
        item.cost_center = cost_center

def make_payment_entry_against_sales_invoice(doc, woocommerce_settings):
    from erpnext.accounts.doctype.payment_entry.payment_entry import get_payment_entry
    payment_entry = get_payment_entry(doc.doctype, doc.name, bank_account=woocommerce_settings.cash_bank_account)
    payment_entry.flags.ignore_mandatory = True
    payment_entry.reference_no = doc.name
    payment_entry.reference_date = nowdate()
    payment_entry.submit()

def create_delivery_note(woocommerce_order, woocommerce_settings, so):
    for fulfillment in woocommerce_order.get("fulfillments"):
        if not frappe.db.get_value("Delivery Note", {"woocommerce_fulfillment_id": fulfillment.get("id")}, "name")\
            and so.docstatus==1:
            dn = make_delivery_note(so.name)
            dn.woocommerce_order_id = fulfillment.get("order_id")
            dn.woocommerce_fulfillment_id = fulfillment.get("id")
            dn.naming_series = woocommerce_settings.delivery_note_series or "DN-woocommerce-"
            dn.items = get_fulfillment_items(dn.items, fulfillment.get("line_items"), woocommerce_settings)
            dn.flags.ignore_mandatory = True
            dn.save()
            frappe.db.commit()

def get_fulfillment_items(dn_items, fulfillment_items, woocommerce_settings):

    return [dn_item.update({"qty": item.get("quantity")}) for item in fulfillment_items for dn_item in dn_items\
            if get_item_code(item) == dn_item.item_code]
    
#def get_discounted_amount(order):
    #discounted_amount = flt(order.get("discount_total") or 0)
    #return discounted_amount

def get_order_items(order_items, woocommerce_settings):
    items = []
    for woocommerce_item in order_items:
        item_code = get_item_code(woocommerce_item)
        items.append({
            "item_code": item_code,
            "rate": woocommerce_item.get("price"),
            "delivery_date": nowdate(),
            "qty": woocommerce_item.get("quantity"),
            "warehouse": woocommerce_settings.warehouse
        })
    return items

def get_item_code(woocommerce_item):
    if cint(woocommerce_item.get("variation_id")) > 0:
        # variation
        item_code = frappe.db.get_value("Item", {"woocommerce_product_id": woocommerce_item.get("variation_id")}, "item_code")
    else:
        # single
        item_code = frappe.db.get_value("Item", {"woocommerce_product_id": woocommerce_item.get("product_id")}, "item_code")

    return item_code


def get_order_taxes(woocommerce_order, woocommerce_settings):
    taxes = []

    for tax in woocommerce_order.get("tax_lines", []):
        woocommerce_tax = get_woocommerce_tax(tax.get("rate_id"))
        rate = woocommerce_tax.get("rate")
        name = woocommerce_tax.get("name")

        taxes.append({
            "charge_type": "Actual",
            "account_head": get_tax_account_head(woocommerce_tax),
            "description": "{0} - {1}%".format(name, rate),
            "rate": rate,
            "tax_amount": flt(tax.get("tax_total") or 0) + flt(tax.get("shipping_tax_total") or 0), 
            "included_in_print_rate": 0,
            "cost_center": woocommerce_settings.cost_center
        })

    taxes = update_taxes_with_fee_lines(taxes, woocommerce_order.get("fee_lines", []), woocommerce_settings)
    taxes = update_taxes_with_shipping_lines(taxes, woocommerce_order.get("shipping_lines", []), woocommerce_settings)

    return taxes


def update_taxes_with_fee_lines(taxes, fee_lines, woocommerce_settings):

    for fee_charge in fee_lines:
        taxes.append({
            "charge_type": "Actual",
            "account_head": woocommerce_settings.fee_account,
            "description": fee_charge["name"],
            "tax_amount": fee_charge["amount"],
            "cost_center": woocommerce_settings.cost_center
        })

    return taxes

def update_taxes_with_shipping_lines(taxes, shipping_lines, woocommerce_settings):
    if not shipping_lines:

        return taxes

    for index, shipping_charge in enumerate(shipping_lines):

        try:
            account_head = get_shipping_account_head(shipping_charge)
            taxes.append({
                "charge_type": "Actual",
                "account_head": account_head,
                "description": shipping_charge["method_title"],
                "tax_amount": flt(shipping_charge["total"]),
                "cost_center": woocommerce_settings.cost_center
            })
        except Exception as e:
            make_woocommerce_log(title="Error Processing Shipping Line", status="Error", method="update_taxes_with_shipping_lines",
                                 message=f"Error processing shipping line {index + 1}: {str(e)}", request_data=shipping_charge, exception=True)


    return taxes



def get_shipping_account_head(shipping):
    shipping_title = shipping.get("method_title")
    
    if shipping_title:
        shipping_title = shipping_title.encode("utf-8").decode("utf-8")

    shipping_account = frappe.db.get_value("woocommerce Tax Account", 
                                           {"parent": "WooCommerce Config", "woocommerce_tax": shipping_title}, "tax_account")
    
    return shipping_account



def get_tax_account_head(tax):
    tax_title = tax.get("name") or tax.get("method_title")
    if tax_title:
        tax_title = tax_title.encode("utf-8").decode("utf-8")

    tax_account =  frappe.db.get_value("woocommerce Tax Account", \
        {"parent": "WooCommerce Config", "woocommerce_tax": tax_title}, "tax_account")

    if not tax_account:
        frappe.throw("Tax Account not specified for woocommerce Tax {0}".format(tax.get("name")))

    return tax_account


def close_synced_woocommerce_orders():
    for woocommerce_order in get_woocommerce_orders():
        if woocommerce_order.get("status").lower() != "cancelled":
        # if woocommerce_order.get("status").lower() != "cancelled" and woocommerce_order.get("status").lower() == "processing":
            order_data = {
                "status": "pending_dispatch"
            }
            try:
                put_request("orders/{0}".format(woocommerce_order.get("id")), order_data)
                    
            except requests.exceptions.HTTPError as e:
                make_woocommerce_log(title=e, status="Error", method="close_synced_woocommerce_orders", message=frappe.get_traceback(),
                    request_data=woocommerce_order, exception=True)

# def close_synced_woocommerce_order(wooid):
#         order_data = {
#             "status": "pending_dispatch"
#         }
#         try:
#             put_request("orders/{0}".format(wooid), order_data)
                
#         except requests.exceptions.HTTPError as e:
#             make_woocommerce_log(title=e.message, status="Error", method="close_synced_woocommerce_order", message=frappe.get_traceback(),
#                 request_data=woocommerce_order, exception=True)


@frappe.whitelist()
def close_synced_woocommerce_order(wooid):
    # woocommerce_order = get_woocommerce_orders(wooid)
    order_data = {
        "status": "pending_dispatch"
    }
    try:
        put_request("orders/{0}".format(wooid), order_data)
    except requests.exceptions.HTTPError as e:
        make_woocommerce_log(title=e.message, status="Error", method="close_synced_woocommerce_order", message=frappe.get_traceback(),
            request_data=order_data, exception=True)
