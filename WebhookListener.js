const url = require('url');
const http = require("http");

module.exports = class WebhookListener {
  port = undefined;
  server = undefined;
  listeners = undefined;

  constructor(port) {
    this.port = port;
    this.listeners = {};

    this.onRequest = this.onRequest.bind(this);
    this.server = http.createServer(this.onRequest).listen(port);
  }

  onRequest(req, res) {
    const buff = [];
    req.on('data', chunk => {
      buff.push(chunk);
    });

    req.on("end", () => {
      const parsedUrl = url.parse(req.url);
      const path = parsedUrl.path;

      const withBody = { ...req, body: Buffer.concat(buff) };

      let status;
      if (this.listeners[path])
        status = this.listeners[path](withBody);

      if (isNaN(status))
        res.writeHead(200);
      else
        res.writeHead(status);
      res.end();
    });
  }

  set(k, v) {
    this.listeners[k] = v;
  }

  remove(k) {
    delete this.listeners[k];
  }

  close() {
    this.server.close();
  }
}