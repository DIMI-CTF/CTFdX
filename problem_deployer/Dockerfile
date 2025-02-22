FROM node:22-alpine

WORKDIR /app

COPY . .

RUN apk update
RUN apk add docker
RUN npm install --production

ENTRYPOINT ["node", "problem_deployer.js"]