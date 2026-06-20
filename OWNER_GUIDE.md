# Owner Guide — AtlasCheckin

Plain-English guide. No technical jargon. Follow the numbered steps.

---

## 1. Finding and Setting the Shop's Allowed IP

The system only lets workers check in when they are on the shop WiFi. To set this up:

1. Stand inside the shop and connect your phone to the shop WiFi (not mobile data).
2. Open this address in your phone's browser: `https://atlascheckin.pages.dev/myip`
3. The page shows a single number — that is your shop's public IP address. Write it down.
4. Run this command on your computer, replacing `YOUR.IP.HERE` with the number you saw:
   ```
   wrangler pages secret put ALLOWED_IPS --project-name atlascheckin
   ```
   When prompted, type the IP address and press Enter.
5. Redeploy so the change takes effect:
   ```
   wrangler pages deploy ./dist --project-name atlascheckin
   ```

**Important:** This only works reliably if your internet provider gives the shop a fixed ("static") IP address. If workers suddenly cannot check in — even though they are on the shop WiFi — the IP address may have changed. Repeat steps 1–5 above. To avoid this happening again, contact your internet provider and ask for a static IP address.

**Note:** Being on the shop WiFi is a deterrent, not proof of physical presence. Someone standing just outside the shop, still connected to the same WiFi network, could also check in. Use your judgement when reviewing records.

---

## 2. Adding a New Worker and Sending Their Check-In URL

1. Open `https://atlascheckin.pages.dev/admin` and log in with your admin password.
2. Scroll down to the **Add New Worker** form.
3. Enter the worker's first name and last name, then click **Add Worker**.
4. The new worker appears in the worker list. Click **Copy URL** next to their name.
5. Paste that URL into a WhatsApp message and send it to the worker.
6. Tell the worker: "Bookmark this link. Open it on the shop WiFi each time you arrive."

Each worker gets a unique link. Do not share one worker's link with another.

---

## 3. Deactivating a Worker Who Has Left

1. Open `https://atlascheckin.pages.dev/admin` and log in.
2. Find the worker in the **Workers** list.
3. Click **Deactivate** next to their name.
4. Their link immediately stops working. If they try to check in, they see a "link not valid" message.

To reactivate them later, click **Activate**.

---

## 4. Reading the Admin Page

- Each row in the check-in table is one check-in event. Workers may check in more than once per day; each tap of the button is a separate row.
- The **earliest check-in** for each worker on a given day is their arrival time.
- The **Status** column shows either **OK** or **REVIEW**.
  - **OK** means the device matched what was recorded last time.
  - **REVIEW** (shown in yellow) means two or more device details changed. This could mean a different device was used — but it can also be caused by a phone software update, a browser update, or a new phone. It is a prompt to look closer, not an accusation.
- The **Flag Reason** column lists which specific details changed (for example: `browserVersion, canvasHash`).
- Use **REVIEW** flags as a starting point for a conversation, not as a verdict.

---

## 5. Resetting a Worker's Baseline When They Get a New Phone

When a worker gets a new phone, their first check-in on the new phone will be flagged as REVIEW because the device is different from what was recorded. To clear this:

1. Open `https://atlascheckin.pages.dev/admin` and log in.
2. Find the worker in the **Workers** list.
3. Click **Reset Baseline** next to their name and confirm.
4. The next time that worker checks in, their new phone is recorded as the new baseline. Future check-ins from that phone will show OK.

---

## 6. Exporting Attendance to CSV for Payroll

1. Open `https://atlascheckin.pages.dev/admin` and log in.
2. Use the date selector to choose the day you want.
3. Click **Export to CSV**.
4. A file downloads to your computer. Open it in Excel or Google Sheets.
5. The file has columns: Worker Name, Time (Singapore), IP Address, Status, Flag Reason.
6. The earliest check-in per worker per day is their start time for that shift.

---

## 7. What To Do If a Worker Cannot Check In

Work through these checks in order:

1. **Are they on the shop WiFi?** Ask them to turn off mobile data and make sure they are connected to the shop WiFi network, not a personal hotspot or mobile data.
2. **Has the shop IP changed?** Open `https://atlascheckin.pages.dev/myip` on a device connected to the shop WiFi. Compare the number shown to the IP in your `ALLOWED_IPS` setting. If they are different, follow the steps in Section 1 to update the allowed IP.
3. **Is the worker still active?** Open the admin page and check that the worker's status shows **Active**, not Inactive.
4. **Is their link correct?** If they lost the link, open the admin page, find their name, click **Copy URL**, and send it to them again on WhatsApp.

If none of the above solves it, contact whoever set up the system for further help.
