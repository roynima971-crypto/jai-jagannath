# JAI JAGANNATH hotel booking website

A single-hotel booking MVP for **JAI JAGANNATH**. It includes a customer-facing room list, customer registration/login, booking requests, an admin dashboard for rooms/bookings, and PostgreSQL persistence. There is intentionally no multi-hotel or marketplace logic.

## Deploy on Render

1. Push this repository to GitHub (already done if you are reading this there).
2. In Render, choose **New → Blueprint**, select this repository, and apply `render.yaml`.
3. Set the prompted `ADMIN_EMAIL` and `ADMIN_PASSWORD` values. Use a unique password with at least 12 characters. Optionally set both `OWNER_EMAIL` and `OWNER_PASSWORD` to create a hotel-owner account; if you leave them blank, the Super Admin account can manage operations.
4. Wait for the PostgreSQL database and web service to finish deploying. Open the service URL; `/api/health` should return `{"ok":true,"hotel":"JAI JAGANNATH"}`.
5. Sign in with the configured admin credentials. Customers can register on the website.

Render free services may sleep when idle and the free database has provider-specific limits. Check Render's current plan, backup, and retention terms before using real guest data. For dependable production use, select an always-on web plan and managed database backups.

## Run locally

Requires Node.js 20+ and PostgreSQL.

```bash
npm install
cp .env.example .env
# Edit .env with your local PostgreSQL connection string and strong secrets.
npm run dev
```

Open <http://localhost:3000>. The server creates the single hotel schema and seeds the configured admin accounts at startup. Do not commit `.env`.

## Included

- One fixed hotel identity: JAI JAGANNATH.
- Public room listing and room status/pricing management.
- Customer signup/login and private booking history.
- Date-overlap validation under a PostgreSQL transaction and room row lock to prevent concurrent double-booking for the same room.
- Admin booking view and booking status updates.
- Password hashing, HttpOnly authentication cookie, login rate limiting, Helmet security headers, parameterized SQL, and server-side validation.

## Not yet connected

This MVP does **not** process payments, send email/SMS, or upload image files to durable object storage. The admin can set an image URL; configure a storage provider such as Cloudinary or S3 before accepting uploaded photos. Do not mark bookings paid manually based on browser data. Add a payment provider with server-side webhook verification before taking online payments. Have the deployment reviewed and test backups, privacy notices, cancellation policies, and local legal requirements before using it for real bookings.
