#!/usr/bin/env node
// Small modules make security ownership and review boundaries mechanically visible.

import { readdirSync, readFileSync, statSync } from 'node:fs'
import { resolve } from 'node:path'

const root = resolve(new URL('../src', import.meta.url).pathname)
const failures = files(root)
  .filter((path) => path.endsWith('.rs'))
  .map((path) => [path, readFileSync(path, 'utf8').split(/\r?\n/u).length - 1])
  .filter(([, lines]) => lines > 149)

if (failures.length > 0) {
  process.stderr.write(failures.map(([path, lines]) => `${path}: ${lines} lines`).join('\n'))
  process.exit(1)
}
process.stdout.write('Rust source-size gate passed\n')

function files(directory) {
  return readdirSync(directory).flatMap((entry) => {
    const path = resolve(directory, entry)
    return statSync(path).isDirectory() ? files(path) : [path]
  })
}
