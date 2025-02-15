require('dotenv').config();

const fs = require('fs');
const path = require('path');
const child_process = require('child_process');

const { Readable } = require('stream');
const { finished } = require('stream/promises');

const base32 = require('base32')
const AdmZip = require("adm-zip");
const FormData = require("form-data");

const { RequestHelper } = require("webhtools");

const ctfdReq = new RequestHelper(`${process.env.CTFD_URI}/api/v1`);
if (process.env.CTFD_TOKEN) ctfdReq.setTokenAuth(process.env.CTFD_TOKEN);
ctfdReq.setContentType("application/json");

const githubReq = new RequestHelper("https://api.github.com/repos/DIMI-CTF/2025_freshman_ctf");
if (process.env.GITHUB_TOKEN) githubReq.setBearerAuth(process.env.GITHUB_TOKEN);

const STATE = { state: 'pending', data: null };
const LAST_JOB = null;

const loadCfg = (path) => {
  const result = {};

  if (!fs.existsSync(path)) return null;
  const config = fs.readFileSync(path, 'utf8');

  const per_line = config.split("\n");
  for (let i=0; i < per_line.length; i++) {
    const target = per_line[i];
    if (target.startsWith("#")) continue;
    if (["__proto__", "prototype"].indexOf(target) !== -1) continue;

    const entry = target.split("=");
    if (entry[1] && entry[1].indexOf(",") !== -1)
      result[entry[0]] = entry[1].split(",");
    else
      result[entry[0]] = entry[1];
  }

  return (key) => {
    if (result.hasOwnProperty(key)) return result[key];
    return null;
  };
}

const searchFlag = (dir, flag, safes = []) => {
  const safeFiles = Array.isArray(safes) ? safes : safes || [];

  const list = fs.readdirSync(dir);
  for (let i = 0; i < list.length; i++) {
    const item = list[i];
    if (fs.lstatSync(path.join(dir, item)).isDirectory()) { searchFlag(path.join(dir, item), flag, safeFiles); continue; }
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
        console.log(normalized_decoded_string);
        throw new Error("Unsafe hardcoded flag found in " + path.join(dir, item));
      }
    }
  }

  return true;
}

async function deploy() {
  fs.rmSync("./repo", { recursive: true, force: true});
  fs.rmSync("./repo.zip", { recursive: true, force: true });

  STATE.state = 'running';
  STATE.data = { detail: "fetching problems" };
  const repo_download_res = await githubReq.get("/zipball");
  if (!repo_download_res.ok) throw new Error("Cannot download repository.");

  const file = path.join(__dirname, "./repo.zip");
  fs.writeFileSync(file, repo_download_res.bytes);

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

  STATE.data = { detail: "packaging", target: null, step: null };
  const existing_problems = (await ctfdReq.get("/challenges?view=admin")).json.data;
  for (let i = 0; i < targets.length; i++) {
    STATE.data.target = targets[i];
    const file = targets[i];
    const base32_file = base32.encode(file);

    // load configs
    STATE.data.step = "loading configuration" ;
    const config = loadCfg(path.join(problem_dir, file, ".ctfdx.cfg"));
    if (!config) continue;

    fs.cpSync(path.join(problem_dir, file), path.join(packaging_dir, file), { recursive: true, force: true });

    // replace REDACTED files
    STATE.data.step = "replacing redacted files" ;
    const redacted = config("REDACTED_FILE");
    fs.rmSync(path.join(packaging_dir, file, ".ctfdx.cfg"), { recursive: true, force: true });
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
    try {
      searchFlag(path.join(packaging_dir, file), config("FLAG"), config("SAFE_FLAG_FILE"));
    } catch (e) {
      continue;
    }

    // compress to zip
    STATE.data.step = "compressing";
    const zip = new AdmZip();
    zip.addLocalFolder(path.join(packaging_dir, file));
    await zip.writeZipPromise(path.join(for_user_dir, `${file}.zip`));

    // build config
    STATE.data.detail = "uploading problems";
    STATE.data.step = "building configuration";
    const type = config("CHALLENGE_TYPE");
    const register_config = {};
    register_config["name"] = config("CHALLENGE_NAME") || file;
    register_config["description"] = fs.existsSync(path.join(packaging_dir, file, "readme.md")) ? fs.readFileSync(path.join(packaging_dir, file, "readme.md"), "utf-8") : config("CHALLENGE_MESSAGE");
    register_config["category"] = config("CHALLENGE_CATEGORY") || "";
    register_config["state"] =  config("CHALLENGE_STATE") || "hidden";
    switch (type) {
      case "standard":
        register_config["type"] = "standard";
        register_config["value"] = config("CHALLENGE_SCORE") || "";
        break;
      case "container":
        // docker build
        const debug1 = await new Promise((accept) => {
          child_process.exec(`docker build . -t ${base32_file}`, { cwd: config("DOCKER_LOCATION") ? path.join(problem_dir, file, config("DOCKER_LOCATION")) : path.join(problem_dir, file) }, accept);
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
        register_config["image"] = `${base32_file}:latest`;
        break;
      case "dynamic":
        register_config["type"] = "dynamic";
        register_config["initial"] = config("CHALLENGE_SCORE") || "";
        register_config["minimum"] = config("DECAYED_MINIMUM") || "";
        register_config["decay"] = config("DECAY_VALUE") || "";
        register_config["function"] = config("DECAY_FUNCTION") || "";
        break;
    }

    // create or modify challenge
    STATE.data.step = "creating/patching problem to ctfd";
    let challenge_id = "";
    const exists = existing_problems.find((e) => e.tags.find((tag) => tag.value === `ctfdx_${base32_file}`));
    if (exists) {
      challenge_id = exists.id;
      await ctfdReq.patch(`/challenges/${challenge_id}`, register_config);
      const get_flag_res = await ctfdReq.get(`/flags?challenge_id=${challenge_id}`);
      if (get_flag_res.json.data.length === 0) {
        await ctfdReq.post("/flags", { challenge: challenge_id, content: config("FLAG"), data: "", type: "static" });
      }else {
        await ctfdReq.patch(`/flags/${get_flag_res.json.data[0].id}`, { challenge: challenge_id, content: config("FLAG"), data: "", type: "static" });
      }
    }else {
      challenge_id = (await ctfdReq.post("/challenges", register_config)).json.data.id;
      await ctfdReq.post("/tags", { challenge: challenge_id, value: `ctfdx_${base32_file}` });
      await ctfdReq.post("/flags", { challenge: challenge_id, content: config("FLAG"), data: "", type: "static" });
    }

    STATE.data.step = "uploading for user file to ctfd";
    if (!!(config("POST_FILE_FOR_USER") || true)) {
      const challenge_files = (await ctfdReq.get(`/challenges/${challenge_id}/files`)).json.data;
      challenge_files.forEach((file) => {
        ctfdReq.delete(`/files/${file.id}`);
      });
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

    STATE.data.detail = null;
    STATE.data.target = null;
    STATE.data.step = null;
  }
  STATE.data = null;
  STATE.state = "done";
}

setInterval(() => {
  process.stdout.write(`\r${JSON.stringify(STATE)}                                                                                                          `);
})

deploy();