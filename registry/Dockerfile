FROM node:22-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --production
COPY dist/ ./dist/
COPY migrations/ ./migrations/
EXPOSE 3100
CMD ["node", "dist/index.js"]
