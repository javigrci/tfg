# Stage 1 — Build de la aplicación React
FROM node:20-alpine AS build

WORKDIR /app
COPY package*.json ./
RUN npm ci

COPY . .

# VITE_API_URL se pasa como build-arg desde docker-compose
# En Docker Compose usa /api/v1 (proxy nginx); en local usa el valor de .env
ARG VITE_API_URL=/api/v1
ENV VITE_API_URL=$VITE_API_URL

RUN npm run build

# Stage 2 — Servidor nginx con los estáticos + proxy de API
FROM nginx:alpine

COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
