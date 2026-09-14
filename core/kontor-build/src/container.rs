use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub platform: String,
    pub image: String,
    pub node: Archive,
    pub wasm_tools: Archive,
    pub wasi_sdk: Archive,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Archive {
    pub version: String,
    pub url: String,
    pub sha256: String,
}

impl Config {
    pub fn read(root: &Path) -> Result<Self> {
        let config: Self = serde_json::from_slice(&fs::read(root.join("tools/build.json"))?)?;
        ensure!(
            matches!(config.platform.as_str(), "linux/arm64" | "linux/amd64"),
            "unsupported build platform"
        );
        let (_, digest) = config
            .image
            .split_once("@sha256:")
            .context("build image must be pinned by SHA256 digest")?;
        ensure!(is_digest(digest), "invalid image digest");
        for archive in [&config.node, &config.wasm_tools, &config.wasi_sdk] {
            ensure!(
                archive.url.starts_with("https://") && is_digest(&archive.sha256),
                "tools must have HTTPS URLs and SHA256 pins"
            );
        }
        Ok(config)
    }
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

pub fn sha256(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let len = file.read(&mut buffer)?;
        if len == 0 {
            break;
        }
        hash.update(&buffer[..len]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

pub struct Container<'a> {
    pub root: &'a Path,
    pub config: &'a Config,
    runtime: String,
    user: Option<String>,
    jobs: u32,
}

impl<'a> Container<'a> {
    pub fn new(
        root: &'a Path,
        config: &'a Config,
        runtime: Option<String>,
        jobs: u32,
    ) -> Result<Self> {
        let runtime = runtime
            .or_else(|| {
                ["podman", "docker"]
                    .into_iter()
                    .find(|runtime| {
                        Command::new(runtime)
                            .arg("--version")
                            .stdout(Stdio::null())
                            .stderr(Stdio::null())
                            .status()
                            .is_ok_and(|s| s.success())
                    })
                    .map(String::from)
            })
            .context("install podman or docker to run the pinned build")?;
        let uid = output(Command::new("id").arg("-u"))?;
        let gid = output(Command::new("id").arg("-g"))?;
        let rootless = runtime == "podman"
            && output(Command::new(&runtime).args([
                "info",
                "--format",
                "{{.Host.Security.Rootless}}",
            ]))? == "true";
        let this = Self {
            root,
            config,
            runtime,
            // Rootless Podman's container root already maps to the host user.
            user: (!rootless).then(|| format!("{uid}:{gid}")),
            jobs,
        };
        let local = Command::new(&this.runtime)
            .args([
                "image",
                "inspect",
                "--format",
                "{{.Os}}/{{.Architecture}}",
                &config.image,
            ])
            .stderr(Stdio::null())
            .output()?;
        if !local.status.success() || String::from_utf8(local.stdout)?.trim() != config.platform {
            checked(Command::new(&this.runtime).args([
                "pull",
                "--platform",
                &config.platform,
                &config.image,
            ]))?;
        }
        let arch = this.text("/build", &[], &["uname", "-m"])?;
        let expected = if config.platform == "linux/arm64" {
            "aarch64"
        } else {
            "x86_64"
        };
        ensure!(
            arch == expected,
            "container architecture {arch} does not match {}",
            config.platform
        );
        Ok(this)
    }

    pub fn command(&self, cwd: &str, env: &[(&str, &str)], args: &[&str]) -> Command {
        let mut command = Command::new(&self.runtime);
        // The platform-specific image was resolved above. Podman can otherwise
        // contact the registry again for every run of a manifest-list digest.
        command.args([
            "run",
            "--rm",
            "--pull",
            "never",
            "--platform",
            &self.config.platform,
        ]);
        if let Some(user) = &self.user {
            command.args(["--user", user]);
        }
        if self.runtime == "podman" {
            command.args(["--security-opt", "label=disable"]);
        }
        command.args(["-v", &format!("{}:/build", self.root.display()), "-w", cwd]);
        for (key, value) in [
            ("CARGO_HOME", "/build/.build-cache/cargo"),
            ("CARGO_BUILD_JOBS", &self.jobs.to_string()),
            ("NPM_CONFIG_CACHE", "/build/.build-cache/npm"),
            ("NPM_CONFIG_USERCONFIG", "/dev/null"),
        ]
        .into_iter()
        .chain(env.iter().copied())
        {
            command.args(["-e", &format!("{key}={value}")]);
        }
        command.arg(&self.config.image).args(args);
        command
    }

    pub fn run(&self, cwd: &str, env: &[(&str, &str)], args: &[&str]) -> Result<()> {
        checked(&mut self.command(cwd, env, args))
    }

    pub fn text(&self, cwd: &str, env: &[(&str, &str)], args: &[&str]) -> Result<String> {
        output(&mut self.command(cwd, env, args))
    }

    pub fn archive(&self, archive: &Archive) -> Result<String> {
        let relative = PathBuf::from(".build-cache/tools").join(&archive.sha256);
        let directory = self.root.join(&relative);
        let container_dir = format!("/build/{}", relative.display());
        if directory.join(".verified").is_file() {
            return Ok(container_dir);
        }
        fs::create_dir_all(self.root.join(".build-cache/downloads"))?;
        let download = format!(".build-cache/downloads/{}.tar.gz", archive.sha256);
        let path = self.root.join(&download);
        if !path.is_file() || sha256(&path)? != archive.sha256 {
            self.run(
                "/build",
                &[],
                &[
                    "curl",
                    "--fail",
                    "--location",
                    "--retry",
                    "3",
                    "--output",
                    &format!("/build/{download}"),
                    &archive.url,
                ],
            )?;
        }
        ensure!(
            sha256(&path)? == archive.sha256,
            "archive checksum mismatch: {}",
            archive.url
        );
        if directory.exists() {
            fs::remove_dir_all(&directory)?;
        }
        fs::create_dir_all(&directory)?;
        self.run(
            "/build",
            &[],
            &[
                "tar",
                "-xzf",
                &format!("/build/{download}"),
                "--strip-components=1",
                "--no-same-owner",
                "-C",
                &container_dir,
            ],
        )?;
        fs::write(directory.join(".verified"), &archive.sha256)?;
        Ok(container_dir)
    }
}

fn checked(command: &mut Command) -> Result<()> {
    let status = command
        .status()
        .with_context(|| format!("start {command:?}"))?;
    ensure!(status.success(), "command failed ({status}): {command:?}");
    Ok(())
}

fn output(command: &mut Command) -> Result<String> {
    let result = command
        .stderr(Stdio::inherit())
        .output()
        .with_context(|| format!("start {command:?}"))?;
    if !result.status.success() {
        io::Write::write_all(&mut io::stderr(), &result.stdout)?;
        bail!("command failed ({}): {command:?}", result.status);
    }
    Ok(String::from_utf8(result.stdout)?.trim().to_owned())
}
