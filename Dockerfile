FROM node:20-alpine
RUN apk add --no-cache openssh-client
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev
COPY server.js ./
COPY lib ./lib
COPY templates ./templates
COPY public ./public
EXPOSE 4000
CMD ["node", "server.js"]