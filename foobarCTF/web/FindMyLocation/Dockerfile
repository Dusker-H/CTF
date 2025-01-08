FROM node:12-buster-slim

WORKDIR /app

COPY src/package*.json ./

ENV PORT 9999
ENV NODE_ENV production
RUN npm install

COPY src .

EXPOSE 9999

CMD ["node","/app/index.js"]
