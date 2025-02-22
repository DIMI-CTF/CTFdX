FROM node:22-alpine

WORKDIR /app

COPY . .

RUN npm install --production

ENTRYPOINT ["node", "problem_deployer.js"]