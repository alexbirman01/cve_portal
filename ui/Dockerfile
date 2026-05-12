FROM node:22-alpine AS build
WORKDIR /app
COPY ui/package*.json /app/
RUN npm ci
COPY ui /app
RUN npm run build

FROM nginx:1.27-alpine
COPY ui/nginx.docker.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80

