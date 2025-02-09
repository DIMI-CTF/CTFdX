require('dotenv').config();

const fs = require('fs');
const path = require('path');
const child_process = require('child_process');

const { Readable } = require('stream');
const { finished } = require('stream/promises');

const base32 = require('base32')
const AdmZip = require("adm-zip");

const url = "https://api.github.com/repos/DIMI-CTF/2025_freshman_ctf";
const githubToken = process.env.GITHUB_TOKEN;
const githubHeader = githubToken ? { "Authorization": `Bearer ${githubToken}` } :  {};

const loadCfg = (path) => {
  const result = {};

  if (!fs.existsSync(path)) throw Error('Could not find file');
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

  const repo_download_res = await fetch(`${url}/zipball/`, { headers: githubHeader });
  if (!repo_download_res.ok) throw new Error("Cannot download repository.");

  const file = path.join(__dirname, "./repo.zip");
  const fileStream = fs.createWriteStream(file, { flags: 'w' });
  await finished(Readable.fromWeb(repo_download_res.body).pipe(fileStream));

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
  fs.mkdirSync(packaging_dir);

  const targets = fs.readdirSync(problem_dir);
  for (let i = 0; i < targets.length; i++) {
    const file = targets[i];
    const image_name = base32.encode(file);
    fs.cpSync(path.join(problem_dir, file), path.join(packaging_dir, file), { recursive: true, force: true });

    // docker build
    const debug1 = await new Promise((accept) => {
      child_process.exec(`docker build . -t ${image_name}`, { cwd: path.join(problem_dir, file) }, accept);
    });
    if (debug1) throw new Error(`${debug1}`);

    // load configs
    const config = loadCfg(path.join(problem_dir, file, ".ctfdx.cfg"));
    console.log(config);

    // replace REDACTED files
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
    searchFlag(path.join(packaging_dir, file), config("FLAG"), config("SAFE_FLAG_FILE"));
  }
}

deploy();