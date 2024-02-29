# Sims

Run simulations to generate benign and malicious cloud logs.

# Deployment

## API

### Local

Please set the env variables in `.env.local` before running commands.

```bash
cp .env.local.example .env.local
```

```bash
# .env.local

# Use 'dev' for local development
TRACECAT__ENV=dev

# OpenAI API key
OPENAI_API_KEY=...

# Optional: OpenAI organization ID
OPENAI_ORG_ID=...
```

Deploy the FastAPI app using `uvicorn`. You may wish to specify the number of workers with the `--workers` flag.

```bash
uvicorn sims.api.server:app --reload
```

### Modal

We use [Modal](https://modal.com) for serverless deployments.

Please set the env variables in `.env.modal` before running commands.

```bash
cp .env.modal.example .env.modal
```

```bash
# .env.modal

# 'dev' or 'prod'.
# Use 'dev' when serving the Modal endpoint from the CLI.
# Use 'prod' when deploying to Modal.
TRACECAT__ENV=prod

# The name of the secret you created in the Modal dashboard
TRACECAT__MODAL_OPENAI_SECRET_NAME=...

# The URL of the client
TRACECAT__FRONTEND_URL=...
```

You will also have to setup a Modal account and the CLI tool to proceed. Please follow the instructions [here](https://modal.com/docs/guide).

Serving the Modal endpoint with hot reload (for development):

```bash
modal serve sims/api/modal_server.py
```

For full deployment:

```bash
modal deploy --name <deployment name> sims/api/modal_server.py
```

## Frontend

### Local

Follow the `pnpm` installation instructions [here](https://pnpm.io/installation).

Configure your `frontend/.env.local` file to point to the API endpoint URL using `NEXT_PUBLIC_API_URL`.

```bash
# frontend/.env.local

# Your API endpoint URL
NEXT_PUBLIC_API_URL=http://localhost:8000
```

Then run the development server with pnpm:

```bash
cd frontend
pnpm dev
```

### Vercel

We recommend depoying the frontend on Vercel, override the `NEXT_PUBLIC_API_URL` in the Vercel dashboard and point the **Root Directory** to `frontend`.
