DIP (Document Intelligence Platform)
=====================================

A global document processing platform combining PDF tools with AI, OCR, and workflow — with privacy-first approach and full Arabic/English support.

## Tech Stack

- **Frontend:** Next.js 16 + TypeScript + Tailwind CSS
- **Backend:** Node.js + TypeScript (Modular Monolith)
- **Database:** PostgreSQL + Prisma ORM
- **Cache/Queue:** Redis + BullMQ
- **Storage:** S3-compatible (Cloudflare R2)
- **AI:** Gemini (initial) + AI Gateway
- **PDF:** pdf-lib (MIT) + PDF.js (Apache-2.0)

## Getting Started

### Prerequisites

- Node.js 20+
- Docker & Docker Compose
- npm or pnpm

### Setup

1. Clone the repository:
   ```bash
   git clone <repo-url>
   cd dip
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Start Docker services (PostgreSQL + Redis):
   ```bash
   npm run docker:up
   ```

4. Set up environment variables:
   ```bash
   cp .env.example .env.local
   ```

5. Run database migrations:
   ```bash
   npm run db:migrate
   ```

6. Start the development server:
   ```bash
   npm run dev
   ```

7. Open [http://localhost:3000](http://localhost:3000)

## Scripts

- `npm run dev` — Start development server
- `npm run build` — Build for production
- `npm run start` — Start production server
- `npm run lint` — Run ESLint
- `npm run db:generate` — Generate Prisma client
- `npm run db:push` — Push schema to database
- `npm run db:migrate` — Run migrations (development)
- `npm run db:studio` — Open Prisma Studio
- `npm run docker:up` — Start Docker services
- `npm run docker:down` — Stop Docker services

## Project Structure

```
dip/
├── src/
│   ├── app/              # Next.js App Router pages
│   │   ├── (tools)/      # Tool pages (merge-pdf, split-pdf, etc.)
│   │   └── (dashboard)/  # Dashboard pages
│   ├── components/       # React components
│   │   ├── ui/           # UI primitives (Button, Card, Input)
│   │   ├── layout/       # Layout components
│   │   └── tools/        # Tool-specific components
│   ├── lib/              # Utility libraries
│   │   ├── db/           # Prisma client
│   │   ├── pdf/          # PDF processing utilities
│   │   ├── ai/           # AI Gateway client
│   │   ├── queue/        # BullMQ queue
│   │   └── storage/      # S3 storage client
│   ├── types/            # TypeScript types
│   └── config/           # App configuration
├── prisma/               # Prisma schema & migrations
├── workers/              # Background workers
├── docker/               # Docker configurations
├── messages/             # i18n translation files
└── public/               # Static assets
```

## Tools (MVP)

### Core PDF Tools (Client-side)
- Merge PDF
- Split PDF
- Compress PDF
- Organize PDF
- Rotate PDF
- Delete Pages
- Extract Pages
- JPG to PDF

### Server-side Tools
- PDF to JPG
- Watermark PDF
- Word to PDF
- PDF to Word
- OCR PDF

### AI Tools
- Summarize PDF
- Chat with PDF
- Extract Data

## Phase 0 foundation

The foundation is intentionally complete before PDF tool delivery: PostgreSQL is
the domain source of truth, Redis backs asynchronous jobs, and object storage
keeps binary content outside the database. The executable Tool Registry in
`src/config/index.ts` is the single definition of every tool's execution mode,
input limits, capabilities, security class, version, and locales.

`GET /api/health` is a deployment health endpoint. Structured logs use stable
event names and can include a correlation or job ID. Session helpers provide
signed, HTTP-only session-cookie primitives; connect them to the sign-in UI
when user-facing authentication is implemented.

Before the first deployment, set production values for every variable in
`.env.example`, create and review a Prisma migration, and configure the
provider-specific S3/R2 adapter behind `src/lib/storage`.

## License

Proprietary — All rights reserved.
