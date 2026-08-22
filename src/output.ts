import { randomBytes } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';

function isWithin(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate);
  return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
}

export interface SafeDestination {
  /** Canonical destination path constructed beneath the real parent. */
  path: string;
  parent: string;
}

/** Resolve a destination without following its final component. */
export function validateExternalDestination(
  destination: string,
  artifactRoot: string,
  label: string,
): SafeDestination {
  const requested = path.resolve(destination);
  let parent: string;
  try {
    parent = fs.realpathSync(path.dirname(requested));
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code ?? 'UNKNOWN';
    throw new Error(`${label} parent must already exist and be resolvable (${code})`);
  }
  if (!fs.statSync(parent).isDirectory()) throw new Error(`${label} parent is not a directory`);
  const resolved = path.join(parent, path.basename(requested));
  try {
    if (fs.lstatSync(requested).isSymbolicLink()) throw new Error(`${label} must not be a symlink`);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }
  const realArtifact = fs.realpathSync(artifactRoot);
  if (isWithin(realArtifact, resolved)) {
    throw new Error(`${label} must be outside the scanned artifact`);
  }
  return { path: resolved, parent };
}

/** Durable same-directory temp + fsync + rename, with cleanup on all failures. */
export function atomicWriteText(destination: SafeDestination, content: string): void {
  const temp = path.join(
    destination.parent,
    `.${path.basename(destination.path)}.casefile-tmp-${process.pid}-${randomBytes(8).toString('hex')}`,
  );
  let fd: number | undefined;
  try {
    fd = fs.openSync(temp, 'wx', 0o600);
    fs.writeFileSync(fd, content, 'utf-8');
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    try {
      if (fs.lstatSync(destination.path).isSymbolicLink()) {
        throw new Error('destination became a symlink before atomic rename');
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }
    fs.renameSync(temp, destination.path);
    const parentFd = fs.openSync(destination.parent, 'r');
    try {
      fs.fsyncSync(parentFd);
    } finally {
      fs.closeSync(parentFd);
    }
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
    try {
      fs.unlinkSync(temp);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }
  }
}
