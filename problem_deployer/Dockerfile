FROM node:22

WORKDIR /app

COPY . .

RUN apt-get update
sudo apt-get install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# Add the repository to Apt sources:
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update

RUN apt-get install -y docker-ce-cli
RUN apt-get install -y tzdata
RUN rm /etc/localtime
RUN ln -s /usr/share/zoneinfo/Asia/Seoul /etc/localtime

RUN npm install --production

ENTRYPOINT ["node", "problem_deployer.js"]