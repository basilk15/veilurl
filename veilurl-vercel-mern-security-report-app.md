# VeilURL: Vercel MERN Security Report App

## Summary

Build **VeilURL**, a polished MERN-style portfolio web app where users enter a URL and receive an instant security-style report. The MVP uses passive public recon so the focus stays on UI quality, deployment polish, MongoDB persistence, and clean full-stack structure.

Approved direction:

- Architecture: **Vercel full-stack**
- Language: **JavaScript + JSX, not TypeScript**
- MVP scan depth: **safe passive recon**
- UI style: **light premium security operations dashboard**
- Concept reference: `/home/basil/.codex/generated_images/019eca36-8377-7ac3-9153-2a64605bf47b/ig_0129682b695accf7016a2fabf1f128819196662d404fc8b4f1.png`

## Tech Stack

Use:

- **React + Vite + JSX**
- **Node.js serverless API functions on Vercel**
- **Express-style route/controller/service organization**
- **MongoDB Atlas**
- **Mongoose**
- **Tailwind CSS**
- **lucide-react**
- **Framer Motion**
- **Recharts** or custom SVG charts
- **Zod** for runtime validation in plain JavaScript

This keeps the project MERN-style:

- MongoDB: Atlas database
- Express-style backend: controllers/services/routes adapted to Vercel serverless functions
- React: JSX frontend
- Node: Vercel API runtime

## App Screens

### Main Scanner Dashboard

Route: `/`

Includes:

- Top header with `VeilURL`, `Vercel Live`, `History`, and `Docs`
- URL input with `Scan URL` button
- Risk score and verdict
- WHOIS summary
- DNS/TLS checks
- Redirect chain
- Header/security signals
- Reputation checks
- Analyst summary
- Recommended actions
- Right-side recent scans panel

### History View

Route: `/history`

Includes:

- Saved scan list from MongoDB
- Search by domain
- Severity filters: `All`, `Low`, `Medium`, `High`, `Critical`
- Clickable report rows
- Empty state

### Report Detail View

Route: `/report/:scanId`

Includes:

- Full saved report
- Re-run scan action
- Copy/share report link

### Docs View

Route: `/docs`

Includes:

- Short architecture explanation
- Notes that MVP uses passive recon scoring
- Roadmap for real WHOIS, reputation APIs, and AI summaries

## Data Shape

Use plain JavaScript objects and Mongoose schemas.

Example report object:

```js
{
  inputUrl: "https://example.com",
  normalizedUrl: "https://example.com",
  domain: "example.com",
  riskScore: 42,
  riskLevel: "medium",
  verdict: "Review recommended",
  summary: "This domain shows moderate risk indicators...",
  checks: {
    whois: {},
    dns: {},
    tls: {},
    redirects: {},
    headers: {},
    reputation: {}
  },
  recommendations: [],
  createdAt: "2026-06-15T00:00:00.000Z",
  updatedAt: "2026-06-15T00:00:00.000Z"
}
```

Risk levels:

```js
["low", "medium", "high", "critical"]
```

## API Design

### `POST /api/scan`

Request:

```js
{
  url: "https://example.com"
}
```

Behavior:

- Validate URL with Zod
- Normalize URL/domain
- Generate passive recon report
- Save report to MongoDB
- Return full report

### `GET /api/reports`

Supports:

```txt
?severity=high&search=example&page=1
```

Returns paginated scan history.

### `GET /api/reports/:id`

Returns a saved scan report.

### `DELETE /api/reports/:id`

Deletes a saved scan report.

## Demo Scan Engine

Create `src/server/services/reconScanner.js`.

Rules:

- Same URL always produces the same report
- Use hash-based seeded values
- No external API calls
- No active crawling
- No AI API call in MVP

Risk score rules:

- HTTP instead of HTTPS: `+20`
- suspicious keyword: `+10` each, max `+25`
- unusual TLD: `+10`
- simulated young domain: `+15`
- weak security headers: `+10`
- simulated reputation warning: `+20`
- cap at `100`

Suspicious keywords:

```js
["login", "verify", "secure", "account", "wallet", "free", "bonus", "reset"]
```

## Analyst Summary

Do not use a live AI API in MVP.

Implement `src/server/services/localNarrator.js`, which generates polished deterministic report text from scan fields.

Name the UI section:

```txt
Analyst Summary
```

Future OpenAI integration can be added later behind the same service boundary.

## UI Design System

Use the approved dashboard concept.

Rules:

- Light professional security dashboard
- White/near-white background
- Graphite text
- Cobalt primary actions
- Green, amber, and red severity states
- Compact panels and rows
- No purple gradients
- No dark SOC theme
- No landing-page hero
- No nested cards

Core components:

```txt
AppShell.jsx
TopNav.jsx
UrlScanForm.jsx
RiskScoreGauge.jsx
VerdictPanel.jsx
CheckStatusRow.jsx
ReportSection.jsx
SeverityChip.jsx
RecentScansPanel.jsx
ReportTabs.jsx
HistoryTable.jsx
EmptyState.jsx
LoadingReportSkeleton.jsx
```

## File Structure

```txt
/
  api/
    scan.js
    reports/
      index.js
      [id].js
  src/
    app/
      App.jsx
      router.jsx
    components/
      shell/
      scanner/
      report/
      history/
      ui/
    lib/
      apiClient.js
      validators.js
      formatters.js
    server/
      db/
        connect.js
      models/
        ScanReport.js
      services/
        reconScanner.js
        localNarrator.js
      controllers/
        scanController.js
        reportController.js
    styles/
      globals.css
  package.json
  vite.config.js
  vercel.json
  .env.example
```

## Environment Variables

Use:

```env
MONGODB_URI=
```

No AI key is required for the MVP.

## Testing Plan

Test:

- URL validation
- URL normalization
- repeatable passive recon output
- risk score boundaries
- severity mapping
- report saving
- report fetching
- report deletion
- dashboard scan flow
- history filters
- mobile responsiveness
- production Vercel deployment

## Deployment Acceptance Criteria

The app is complete when:

- `npm run build` succeeds
- Vercel deployment works
- `POST /api/scan` works in production
- MongoDB saves scan history
- History persists after reload
- UI matches the approved light dashboard direction
- No TypeScript files are used
- No secret values are committed

## Explicit Assumptions

- The app will be written in **JavaScript/JSX only**
- The workspace starts empty
- MongoDB Atlas will be used for persistence
- The MVP uses passive recon data
- Real WHOIS, blacklist, TLS, and AI APIs are future enhancements
