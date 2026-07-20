# ProcTree frontend — build the Vite SPA, serve it (and proxy /api) via nginx.
FROM node:22-slim AS build
WORKDIR /app

# Install deps against lockfile-ish state for caching.
COPY frontend/package.json ./package.json
RUN npm install

# Build.
COPY frontend/ ./
RUN npm run build

# --- runtime ---
FROM nginx:1.27-alpine AS runtime
RUN rm /etc/nginx/conf.d/default.conf
COPY deploy/nginx.conf /etc/nginx/conf.d/proctree.conf
COPY --from=build /app/dist /usr/share/nginx/html
# Rules are also served from the SPA origin for fully offline detection.
COPY --from=build /app/public/rules /usr/share/nginx/html/rules
EXPOSE 8080
CMD ["nginx", "-g", "daemon off;"]
