require('dotenv').config();

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const child_process = require('child_process');

const { Client, GatewayIntentBits, SlashCommandBuilder, MessageFlags, PermissionsString } = require('discord.js');
const AdmZip = require('adm-zip');
const FormData = require('form-data');

const EmbedManager = require('./EmbedManager');
const WebhookListener = require('./WebhookListener');
const { RequestHelper } = require('webhtools');

const STATE = { state: 'pending', data: { detail: null, target: null, step: null } };
let discord_status_channel = process.env.DISCORD_STATUS_CHANNEL;
let discord_log_channel = process.env.DISCORD_LOG_CHANNEL;
/** if deploy triggered during deploy */
let shouldRedeploy = false;

/** delayed deploy */
let deploy_reservation_generated = [];

const ctfdReq = new RequestHelper(`${process.env.CTFD_URI}/api/v1`);
if (process.env.CTFD_TOKEN) ctfdReq.setTokenAuth(process.env.CTFD_TOKEN);
ctfdReq.setContentType("application/json");

const githubReq = new RequestHelper(process.env.GITHUB_REPO_URL);
if (process.env.GITHUB_TOKEN) githubReq.setBearerAuth(process.env.GITHUB_TOKEN);

const discord_client = new Client({ intents: [GatewayIntentBits.Guilds] });

const SCORES = {
  init: {
    superhard: 3000,
    hard: 2000,
    medium: 1500,
    easy: 1000,
  },
  low: {
    superhard: 2000,
    hard: 1000,
    medium: 500,
    easy: 100,
  }
}

const updateState = async () => {

}

const sendError = async (what, e) => {
  const embed = new EmbedManager();
  embed.setTitle("Error occurred");
  embed.setDescription(`During ${what} deploying.`)
  embed.addFields({ name: "state", value: JSON.stringify(STATE) }, { name: e.name, value: e.message }, { name: "Stack trace", value: e.stack });
  embed.setFooter({ text: `Triggered at ${new Date()}` });
  embed.setColor("Red");
  await discord_client.channels.cache.get(discord_log_channel).send({ embeds: [embed] });
}

const loadCfg = (path) => {
  const result = {};

  if (!fs.existsSync(path)) return null;
  const config = fs.readFileSync(path, 'utf8').replaceAll("\r", "");

  const per_line = config.split("\n");
  for (let i=0; i < per_line.length; i++) {
    const target = per_line[i];
    if (!target || target.startsWith("#")) continue;
    if (["__proto__", "prototype"].indexOf(target) !== -1) continue;

    const entry = target.split("=");
    result[entry[0]] = entry[1];
  }

  return (key, array=false) => {
    if (result[key]) return array ? result[key].split(",") : result[key];
    return null;
  };
}

const searchFlag = (dir, flag, safes = [], replace) => {
  // flag = /^.+\{(?<target>.+)}$/.exec(flag).groups.target || flag;

  const safeFiles = Array.isArray(safes) ? safes : safes || [];

  const list = fs.readdirSync(dir);
  for (let i = 0; i < list.length; i++) {
    const item = list[i];
    if (fs.lstatSync(path.join(dir, item)).isDirectory()) { searchFlag(path.join(dir, item), flag, safeFiles, replace); continue; }
    if (safeFiles.find(safe => {
      const withoutSlashStart = safe.startsWith("/") ? safe.slice(1, dir.length) : safe;
      const withoutSlashEnd = withoutSlashStart.endsWith("/") ? withoutSlashStart.slice(0, dir.length - 1) : withoutSlashStart;
      return path.join(dir, item).indexOf(withoutSlashEnd) !== -1
    })) continue;

    const searchEncoding = ["ascii", "utf-8", "utf-16le", "ucs-2", "latin1"];
    for (let j = 0; j < searchEncoding.length; j++) {
      const strings = fs.readFileSync(path.join(dir, item), searchEncoding[j]);
      const normalized_decoded_string = strings.normalize("NFC");
      const normalized_flag = flag.normalize("NFC");
      if (normalized_decoded_string.indexOf(normalized_flag) !== -1) {
        if (replace === "true")
          fs.writeFileSync(path.join(dir, item), strings.replaceAll(flag, "[REDACTED]"));
        else
          throw new Error("Unsafe hardcoded flag found in " + path.join(dir, item));
      }
    }
  }

  return true;
}

/** time: YYYY-MM-DDTHH:mm */
const isBefore = (time) => {
  const current = new Date();
  const target = new Date(time);
  return target > current
}
const isAfter = (time) => {
  const current = new Date();
  const target = new Date(time);
  return target < current
}

async function deploy(manual) {
  if (STATE.state === 'running') {
    shouldRedeploy = true;
    return;
  }
  shouldRedeploy = false;
  const start = Date.now();

  fs.rmSync("./repo", { recursive: true, force: true});
  fs.rmSync("./repo.zip", { recursive: true, force: true });

  STATE.state = 'running';
  STATE.data = { detail: "fetching problems" };
  
  const repo_download_res = await githubReq.get("/zipball", null, path.join(__dirname, "./repo.zip"));
  if (!repo_download_res.ok) throw new Error("Cannot download repository.");

  const unzip = new AdmZip(path.join(__dirname, "./repo.zip"));
  fs.mkdirSync(path.join(__dirname, "repo"));
  unzip.extractAllTo(path.join(__dirname, "repo"), true);

  const name = fs.readdirSync(path.join(__dirname, "repo"))[0];
  fs.readdirSync(path.join(__dirname, `repo/${name}`)).forEach((e) => { fs.cpSync(path.join(__dirname, `repo/${name}/${e}`), path.join(__dirname, `repo/${e}`), { recursive: true, force: true }); });
  fs.readdirSync(path.join(__dirname, `repo`)).filter(e => e.startsWith(".")).forEach((e) => { fs.rmSync(path.join(__dirname, `repo/${e}`), { recursive: true, force: true }); });
  fs.rmSync(path.join(__dirname, `repo/${name}`), { recursive: true, force: true });

  const problem_dir = path.join(__dirname, "repo");
  const packaging_dir = path.join(__dirname, "packaging");
  const for_user_dir = path.join(__dirname, "for_user");
  fs.rmSync(packaging_dir, { recursive: true, force: true });
  fs.rmSync(for_user_dir, { recursive: true, force: true });
  fs.mkdirSync(packaging_dir);
  fs.mkdirSync(for_user_dir);

  const targets = fs.readdirSync(problem_dir);

  deploy_reservation_generated = [];

  STATE.data = { detail: null, target: null, step: null };
  let deploy_count = 0;
  let without = [];
  const existing_problems = (await ctfdReq.get("/challenges?view=admin")).json.data;
  for (let i = 0; i < targets.length; i++) {
    try {
      STATE.data.detail = "packaging";
      STATE.data.target = targets[i];
      const file = targets[i];
      const sha256_file = crypto.createHash('sha1').update(file).digest('hex');

      // load configs
      STATE.data.step = "loading configuration";
      
      const config = loadCfg(path.join(problem_dir, file, ".ctfdx.cfg"));
      if (!config) { without.push(STATE.data.target); continue; }

      fs.cpSync(path.join(problem_dir, file), path.join(packaging_dir, file), {recursive: true, force: true});
      if (fs.existsSync(path.join(packaging_dir, file, "readme.md"))) {
        fs.rmSync(path.join(packaging_dir, file, "readme.md"), { force: true, recursive: true });
      }

      // replace REDACTED files
      STATE.data.step = "replacing redacted files";
      
      const redacted = config("REDACTED_FILE", true);
      fs.rmSync(path.join(packaging_dir, file, ".ctfdx.cfg"), {recursive: true, force: true});
      if (redacted) {
        if (typeof redacted === "string")
          fs.writeFileSync(path.join(packaging_dir, file, redacted), "[REDACTED]");
        else {
          for (let j = 0; j < redacted.length; j++) {
            fs.writeFileSync(path.join(packaging_dir, file, redacted[j]), "[REDACTED]");
          }
        }
      }

      // flag searching
      STATE.data.step = "searching flags";
      searchFlag(path.join(packaging_dir, file), config("FLAG"), config("SAFE_FLAG_FILE", true), config("REPLACE_FLAG"));

      // compress to zip
      if ((config("POST_FILE_FOR_USER") || "true") === "true") {
        STATE.data.step = "compressing";
        
        const zip = new AdmZip();
        zip.addLocalFolder(path.join(packaging_dir, file));
        await zip.writeZipPromise(path.join(for_user_dir, `${file}.zip`));
      }

      // build config
      STATE.data.detail = "uploading problems";
      STATE.data.step = "building configuration";
      
      const type = config("CHALLENGE_TYPE");
      const register_config = {};
      const difficulty = config("CHALLENGE_DIFFICULTY");
      const score = SCORES.init[difficulty] || 100;
      const score_low = SCORES.low[difficulty] || 100;
      register_config["name"] = config("CHALLENGE_NAME") || file;
      register_config["description"] = fs.existsSync(path.join(problem_dir, file, "readme.md")) ? fs.readFileSync(path.join(problem_dir, file, "readme.md"), "utf-8") : config("CHALLENGE_MESSAGE");
      register_config["category"] = config("CHALLENGE_CATEGORY") || "";
      register_config["state"] = config("CHALLENGE_STATE") || "hidden";
      if (config("DEPLOY_AFTER")) {
        if (!(/^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])T\d{2}:\d{2}$/.test(config("DEPLOY_AFTER"))))
          throw new Error("DEPLOY_AFTER format is not acceptable.");
      }
      if (config("DEPLOY_AFTER") && isBefore(config("DEPLOY_AFTER"))) {
        deploy_reservation_generated.push(config("DEPLOY_AFTER"));
        without.push(`${STATE.data.target} (due to delayed deploy)`);
        continue;
      }
      switch (type) {
        case "standard":
          register_config["type"] = "standard";
          register_config["value"] = config("CHALLENGE_SCORE") || "";
          break;
        case "container":
          // docker build
          const debug1 = await new Promise((accept) => {
            child_process.exec(`docker build . -t "${sha256_file}"`, {cwd: config("DOCKER_LOCATION") ? path.join(problem_dir, file, config("DOCKER_LOCATION")) : path.join(problem_dir, file)}, accept);
          });
          if (debug1) throw new Error(`${debug1}`);
          register_config["type"] = "container";
          register_config["connection_info"] = "Container";
          register_config["initial"] = config("CHALLENGE_SCORE") || "";
          register_config["minimum"] = config("DECAYED_MINIMUM") || "";
          register_config["decay"] = config("DECAY_LIMIT") || "";
          register_config["ctype"] = config("DOCKER_CONNECT_TYPE") || "";
          register_config["port"] = config("DOCKER_PORT") || "";
          register_config["command"] = config("DOCKER_COMMAND") || "";
          register_config["image"] = `${sha256_file}:latest`;

          if (difficulty) {
            register_config["initial"] = score;
            register_config["minimum"] = score_low;
            register_config["decay"] = 10;
          }
          break;
        case "dynamic":
          register_config["type"] = "dynamic";
          register_config["initial"] = config("CHALLENGE_SCORE") || "";
          register_config["minimum"] = config("DECAYED_MINIMUM") || "";
          register_config["decay"] = config("DECAY_VALUE") || "";
          register_config["function"] = (config("DECAY_FUNCTION") || "").toLowerCase();

          if (difficulty) {
            register_config["initial"] = score;
            register_config["decay"] = (score - score_low) / 10;
            register_config["minimum"] = score_low;
            register_config["function"] = "linear";
          }
          break;
        // TODO: extension
      }

      // create or modify challenge
      STATE.data.step = "creating/patching problem to ctfd";
      
      let challenge_id = "";
      const exists = existing_problems.find((e) => e.tags.find((tag) => tag.value === `ctfdx_${sha256_file}`));
      if (exists) {
        challenge_id = exists.id;
        await ctfdReq.patch(`/challenges/${challenge_id}`, register_config);
        const get_flag_res = await ctfdReq.get(`/flags?challenge_id=${challenge_id}`);
        if (get_flag_res.json.data.length === 0) {
          await ctfdReq.post("/flags", {challenge: challenge_id, content: config("FLAG"), data: "", type: "static"});
        } else {
          await ctfdReq.patch(`/flags/${get_flag_res.json.data[0].id}`, {
            challenge: challenge_id,
            content: config("FLAG"),
            data: "",
            type: "static"
          });
        }
        const challenge_tags = (await ctfdReq.get(`/challenges/${challenge_id}/tags`)).json.data;
        challenge_tags.forEach((tag) => {
          ctfdReq.delete(`/tags/${tag.id}`);
        });
        await ctfdReq.post("/tags", {challenge: challenge_id, value: `difficulty: ${difficulty}`});
        await ctfdReq.post("/tags", {challenge: challenge_id, value: `ctfdx_${sha256_file}`});
      } else {
        challenge_id = (await ctfdReq.post("/challenges", register_config)).json.data.id;
        await ctfdReq.post("/tags", {challenge: challenge_id, value: `difficulty: ${difficulty}`});
        await ctfdReq.post("/tags", {challenge: challenge_id, value: `ctfdx_${sha256_file}`});
        await ctfdReq.post("/flags", {challenge: challenge_id, content: config("FLAG"), data: "", type: "static"});
      }

      STATE.data.step = "uploading for user file to ctfd";
      
      const challenge_files = (await ctfdReq.get(`/challenges/${challenge_id}/files`)).json.data;
      challenge_files.forEach((file) => {
        ctfdReq.delete(`/files/${file.id}`);
      });
      if ((config("POST_FILE_FOR_USER") || "true") === "true") {
        // req helper not work!
        const formData = new FormData();
        formData.append("type", "challenge");
        formData.append("challenge_id", challenge_id);
        formData.append("file", fs.createReadStream(path.join(for_user_dir, `${file}.zip`)), `${encodeURIComponent(file)}.zip`);
        formData.submit({
          method: "POST",
          headers: {
            "Authorization": `Token ${process.env.CTFD_TOKEN}`,
            ...formData.getHeaders(),
          },
          protocol: process.env.CTFD_URI.split("//")[0],
          host: process.env.CTFD_URI.split("//")[1].split(":")[0],
          port: process.env.CTFD_URI.split("//")[1].split(":")[1],
          path: "/api/v1/files"
        });
      }

      STATE.data.step = null;
      deploy_count++;
    } catch (err) {
      console.log(err);
      without.push(`${STATE.data.target} (due to ${err.message})`);
      await sendError("individual", err);
    }
  }
  STATE.state = "done";
  STATE.data.detail = null;
  STATE.data.target = null;
  STATE.data.step = null;


  const embed = new EmbedManager();
  embed.setTitle(`${manual ? "Manual" : "Automatic"} Deploy Success`);
  embed.setDescription(`Successfully deployed ${deploy_count} problems in ${(Date.now() - start)/1000}s`)
  if (without.length > 0) {
    embed.addFields({ name: "except", value: without.join("\n") });
  }
  if (manual) embed.setAuthor({ name: manual.globalName, iconURL: manual.avatarURL() });
  embed.setFooter({ text: `Issued at ${new Date()}` });
  embed.setColor("Green");
  await discord_client.channels.cache.get(discord_log_channel).send({ embeds: [embed] });

  if (shouldRedeploy) {
    const embed = new EmbedManager();
    embed.setTitle("Re-deploy triggered");
    embed.setDescription("Due to ignored deploy request during deploying.");
    embed.setFooter({ text: `Triggered at ${new Date()}` });
    embed.setColor("Aqua");
    await discord_client.channels.cache.get(discord_log_channel).send({ embeds: [embed] });
    shouldRedeploy = false;
    await deploy();
  }

  // fs.rmSync("./repo", { recursive: true, force: true });
  // fs.rmSync("./packaging", { recursive: true, force: true });
  // fs.rmSync("./for_user", { recursive: true, force: true });
  // fs.rmSync("./repo.zip", { recursive: true, force: true });

  STATE.state = "pending";
  }

discord_client.on("interactionCreate", async (interaction) => {
  console.log(interaction.commandName);
  const member = interaction.guild.members.cache.find((m) => m.id === interaction.user.id);
  const role = member.roles.highest;
  const permissions = role.permissions.serialize();
  if (!permissions["Administrator"]) {
    await interaction.reply({ content: `명령어 실행에 권한이 부족합니다.`, flags: MessageFlags.Ephemeral })
    return;
  }
  switch (interaction.commandName) {
    case "set-log-channel":
      discord_status_channel = interaction.channelId;
      await interaction.reply({ content: `Successfully set the ctfdx status channel as <#${discord_status_channel}>`, flags: MessageFlags.Ephemeral });
      break;
    case "set-status-channel":
      discord_log_channel = interaction.channelId;
      await interaction.reply({ content: `Successfully set the ctfdx log channel as <#${discord_log_channel}>`, flags: MessageFlags.Ephemeral });
      break;
    case "deploy":
      await interaction.reply({ content: "Deploying...", flags: MessageFlags.Ephemeral });
      try {
        await deploy(interaction.user);
      }catch (e) {
        console.error(e);
        await sendError("manual", e);

        STATE.state = "error";
        STATE.data.detail = "Error occurred during deploying. Waiting for next deploy.";
        STATE.data.target = null;
        STATE.data.step = null;
      }
      break;
  }
});

setInterval(async () => {
  if (STATE.state === "running") return;
  if (deploy_reservation_generated.some(drg => isAfter(drg))) {
    const embed = new EmbedManager();
    embed.setTitle("Delayed Deploy triggered");
    embed.setFooter({ text: `Triggered at ${new Date()}` });
    embed.setColor("Aqua");
    await discord_client.channels.cache.get(discord_log_channel).send({ embeds: [embed] });
    await deploy();
  }
}, 10000);

discord_client.once("ready", (readyClient) => {
  console.log(`Client ready. Logged in as ${readyClient.user.tag} at ${new Date()}`);

  const commands = [
    new SlashCommandBuilder()
      .setName("ping")
      .setDescription("pong"),
    new SlashCommandBuilder()
      .setName("set-notice-channel")
      .setDescription("Set default notice channel for ctfdx"),
    new SlashCommandBuilder()
      .setName("set-log-channel")
      .setDescription("Set default log channel for ctfdx"),
    new SlashCommandBuilder()
      .setName("deploy")
      .setDescription("Deploy problem to ctfd"),
  ];

  commands.forEach(async (command) => {
    // discord_client.application.commands.set([]);
    // discord_client.guilds.cache.get("914879556303847434").commands.set([]);
    await discord_client.application.commands.create(command);
    // discord_client.guilds.cache.get("914879556303847434").commands.create(command);
  });

  // setInterval(() => {
  //   updateState();
  // }, 2000);
});
discord_client.login(process.env.DISCORD_TOKEN);

const webhookListener = new WebhookListener(3000);
webhookListener.set("/deploy", async (req) => {
  const body = JSON.parse(decodeURIComponent(req.body.toString()).replace("payload=", ""));

  const embed = new EmbedManager();
  embed.setTitle("Deploy triggered");
  embed.setURL(body.compare);
  embed.setAuthor({ name: body.sender.login, iconURL: body.sender.avatar_url, url: body.sender.url });
  embed.setDescription("By github webhook.");
  embed.addFields({ name: "commits", value: body.commits.map((c) => `[${(c.message.replace(/\+/g, ' '))}](${c.url})`).join("\n")});
  embed.setFooter({ text: `Triggered at ${new Date()}` });
  embed.setColor("Aqua");
  await discord_client.channels.cache.get(discord_log_channel).send({ embeds: [embed] });
  try {
    await deploy();
  }catch (e) {
    console.error(e);
    await sendError("automatic", e);

    STATE.state = "error";
    STATE.data.detail = "Error occurred during deploying. Waiting for next deploy.";
    STATE.data.target = null;
    STATE.data.step = null;
  }
  return 200;
});

// deploy();