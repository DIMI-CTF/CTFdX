FROM node:22-alpine

WORKDIR /app

COPY package.json .
COPY package-lock.json .
COPY EmbedManager.js .
COPY problem_deployer.js .
COPY .env .

RUN npm install --production

ENTRYPOINT ["node", "problem_deployer.js"]