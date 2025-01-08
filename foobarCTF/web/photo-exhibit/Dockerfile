FROM node:16-buster-slim
WORKDIR /app
COPY src/package*.json ./
RUN npm ci --only=production
COPY src ./
EXPOSE 3000
ENTRYPOINT [ "./run-me.sh" ]
