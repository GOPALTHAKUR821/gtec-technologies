G TEC TECHNOLOGEIES — FINAL CART + ADMIN + PRODUCT + ORDER TRACKING

START
1. Extract this ZIP into a new folder.
2. Double-click START-GTEC.bat.
3. Open http://localhost:3000
4. For Admin use the Admin link.

CUSTOMER TRACKING
- Customer opens Track Order.
- Enters the same 10-digit contact/mobile number used for the order.
- All orders linked to that number are shown with current admin-set status, status update time, total, products and shipping-from information.
- Every tracking request is logged in SQLite for the admin portal.

ADMIN
- Orders are stored in gtec.sqlite.
- Admin can update order status: New, Contacted, Confirmed, Dispatched, Delivered, Cancelled.
- Each status change records status_updated_at.
- Admin > Tracking Activity shows which customer contact number checked status, how many times, how many orders were checked, and the last check time.
- Each order also shows its tracking-check count and last check time.
- Product add/edit/photo/delete uses the same database.

NOTE
The tracking feature reports the latest status entered by the admin. It is not live courier GPS tracking unless a courier API is connected.
