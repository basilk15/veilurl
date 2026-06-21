# VeilURL

VeilURL is a MERN-style URL security analysis dashboard built with React, Vercel API routes, MongoDB Atlas, and safe passive recon.

Users enter a URL and receive a concise report with threat scoring, web posture signals, DNS records, RDAP/WHOIS metadata, redirect behavior, TLS certificate details, HTTP security headers, and well-known file checks.

## Features

- React + Vite frontend written in JSX
- Vercel serverless API routes
- MongoDB Atlas persistence with Mongoose
- Safe passive recon only, with private-network target blocking
- DNS checks for A, AAAA, MX, NS, TXT, SPF, and DMARC
- RDAP/WHOIS lookup where available
- HTTP redirect chain inspection
- TLS certificate metadata
- HTTP security header checks
- `security.txt` and `robots.txt` checks
- CSV export, report history, watchlist, settings, and integration views

## Safety Scope

VeilURL is intentionally passive. It does not perform port scanning, brute forcing, crawling, subdomain enumeration, exploitation, or vulnerability scanning.

The backend rejects localhost, private IP ranges, link-local ranges, documentation ranges, multicast ranges, and private-resolving hosts.

## Tech Stack

- React
- Vite
- JavaScript + JSX
- Vercel API routes
- MongoDB Atlas
- Mongoose
- Zod
- lucide-react

## Local Setup

```bash
npm install
cp .env.example .env.local
npm run dev
```

Add your MongoDB Atlas connection string to `.env.local`:

```bash
MONGODB_URI=your_mongodb_connection_string
```

For Vercel-style local API routing:

```bash
vercel dev
```

## Build

```bash
npm run build
```

## Environment Variables

| Name          | Required | Description                                                                                                   |
| ------------- | -------- | ------------------------------------------------------------------------------------------------------------- |
| `MONGODB_URI` | Optional | Enables persistent scan history in MongoDB Atlas. Without it, the app falls back to in-memory/sample reports. |

## Deployment

This project is designed for Vercel. Add `MONGODB_URI` in Vercel project environment variables before production deployment.

## Project Status

This is a portfolio-focused full-stack security dashboard. Current recon is safe and passive. Planned next integrations include Google Safe Browsing, VirusTotal, scheduled monitoring, PDF export, and AI report narration.
