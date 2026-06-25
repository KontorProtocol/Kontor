import { hex } from "@scure/base";

import type {
  BuildProvenance as WireBuildProvenance,
  CommitId as WireCommitId,
  Forge as WireForge,
  Platform as WirePlatform,
  ProvenanceEntry as WireProvenanceEntry,
} from "./bindings.js";

/**
 * Reproducible-build provenance for a published contract: where the source lives
 * (`source`), the pinned build environment (`image`, a digest-pinned OCI ref like
 * `registry/name@sha256:…`), and the `platform` it was built on. A verifier
 * rebuilds `source` in `image` on `platform` and checks the bytes match.
 */
export interface BuildProvenance {
  source: Source;
  image: string;
  platform: Platform;
}

export interface Source {
  forge: Forge;
  owner: string;
  repo: string;
  /** Git commit as hex — 40 chars (SHA-1) or 64 (SHA-256). */
  commit: string;
}

/** VCS host; `{ other }` carries the hostname for self-hosted forges. */
export type Forge =
  | "GitHub"
  | "GitLab"
  | "Bitbucket"
  | "Codeberg"
  | { other: string };

/** Build platform, in Docker `--platform` form. */
export type Platform = "linux/amd64" | "linux/arm64";

const PLATFORM_TO_WIRE: Record<Platform, WirePlatform> = {
  "linux/amd64": "LinuxAmd64",
  "linux/arm64": "LinuxArm64",
};
const PLATFORM_FROM_WIRE: Record<string, Platform> = {
  LinuxAmd64: "linux/amd64",
  LinuxArm64: "linux/arm64",
};

function forgeToWire(f: Forge): WireForge {
  return typeof f === "string" ? f : { Other: f.other };
}
function forgeFromWire(f: WireForge): Forge {
  return typeof f === "string" ? f : { other: f.Other };
}

function commitToWire(commit: string): WireCommitId {
  const bytes = [...hex.decode(commit)];
  if (bytes.length === 20) return { Sha1: bytes };
  if (bytes.length === 32) return { Sha256: bytes };
  throw new Error(
    `commit must be 40 (SHA-1) or 64 (SHA-256) hex chars, got ${commit.length}`,
  );
}
function commitFromWire(c: WireCommitId): string {
  const bytes = "Sha1" in c ? c.Sha1 : c.Sha256;
  return hex.encode(Uint8Array.from(bytes));
}

/** Friendly → wire (serde JSON) shape, for `Inst` serialization. */
export function provenanceToWire(p: BuildProvenance): WireBuildProvenance {
  return {
    source: {
      forge: forgeToWire(p.source.forge),
      owner: p.source.owner,
      repo: p.source.repo,
      commit: commitToWire(p.source.commit),
    },
    image: p.image,
    platform: PLATFORM_TO_WIRE[p.platform],
  };
}

/** One entry in a contract's provenance log (oldest first; last = current). */
export interface ProvenanceEntry {
  height: number;
  txIndex: number;
  /** The signer that authored this entry (the publisher). */
  authorSignerId: number;
  provenance: BuildProvenance;
}

export function provenanceEntryFromWire(
  e: WireProvenanceEntry,
): ProvenanceEntry {
  return {
    height: e.height,
    txIndex: e.tx_index,
    authorSignerId: e.author_signer_id,
    provenance: provenanceFromWire(e.provenance),
  };
}

/** Wire → friendly, for decoding op/API responses. */
export function provenanceFromWire(w: WireBuildProvenance): BuildProvenance {
  const platform = PLATFORM_FROM_WIRE[w.platform as string];
  if (platform === undefined) {
    throw new Error(`unknown build platform: ${w.platform as string}`);
  }
  return {
    source: {
      forge: forgeFromWire(w.source.forge),
      owner: w.source.owner,
      repo: w.source.repo,
      commit: commitFromWire(w.source.commit),
    },
    image: w.image,
    platform,
  };
}
