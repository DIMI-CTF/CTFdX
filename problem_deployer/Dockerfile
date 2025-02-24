FROM node:22

WORKDIR /app

COPY . .

RUN apt-get update
RUN apt-get install -y docker
RUN apt-get install -y tzdata
RUN rm /etc/localtime
RUN ln -s /usr/share/zoneinfo/Asia/Seoul /etc/localtime

RUN npm install --production

ENTRYPOINT ["node", "problem_deployer.js"]