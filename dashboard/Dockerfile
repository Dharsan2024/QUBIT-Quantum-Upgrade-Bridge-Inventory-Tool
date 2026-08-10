FROM node:22-alpine AS builder

WORKDIR /app

# Install dependencies (lockfile-frozen)
COPY package.json package-lock.json ./
RUN npm ci

# Build with a RELATIVE API base so the browser calls same-origin /api/v1, which nginx
# reverse-proxies to the api container. VITE_* vars are baked in at build time.
ARG VITE_API_BASE=/api/v1
ENV VITE_API_BASE=$VITE_API_BASE
# Default bearer token baked into the bundle. MUST match the api service's QUBIT_API_TOKEN
# (docker-compose.yml) or every request 401s "Invalid API token" out of the box.
ARG VITE_API_TOKEN=dev_token
ENV VITE_API_TOKEN=$VITE_API_TOKEN

# Copy source and build
COPY . .
RUN npm run build

FROM nginx:alpine
# Static build output
COPY --from=builder /app/dist /usr/share/nginx/html
# SPA + /api reverse-proxy config
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
