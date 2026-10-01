#!/usr/bin/env node
// This gate preserves the provider-neutral minimum supported Rust contract.

import { spawnSync } from 'node:child_process'

const supported = [1, 95, 0]
const result = spawnSync(
  'cargo',
  ['metadata', '--locked', '--offline', '--format-version', '1'],
  { cwd: new URL('..', import.meta.url), encoding: 'utf8' },
)

if (result.status !== 0) {
  process.stderr.write(result.stderr)
  process.exit(result.status ?? 1)
}

const metadata = JSON.parse(result.stdout)
const root = metadata.packages.find((item) => item.name === 'zixcel-openai-auth')
const failures = []

if (!root || root.rust_version !== '1.95') {
  failures.push('root rust-version must remain 1.95')
}
if (JSON.stringify(root?.publish) !== JSON.stringify(['zixcel-private'])) {
  failures.push('package must target zixcel-private only')
}

for (const item of metadata.packages) {
  if (item.name !== root?.name && !item.source?.startsWith('registry+')) {
    failures.push(`${item.name}: dependency source is not a registry`)
  }
  if (item.id === root?.id
    && item.targets.some((target) => target.kind.includes('custom-build'))) {
    failures.push('root package custom build script is not permitted')
  }
  if (item.rust_version && newer(parse(item.rust_version), supported)) {
    failures.push(`${item.name}@${item.version}: MSRV ${item.rust_version} exceeds 1.95.0`)
  }
}

if (failures.length > 0) {
  process.stderr.write(`${failures.join('\n')}\n`)
  process.exit(1)
}
process.stdout.write(`MSRV gate passed for ${metadata.packages.length} packages\n`)

function parse(value) {
  return value.split('.').slice(0, 3).map((part) => Number.parseInt(part, 10) || 0)
}

function newer(left, right) {
  return left.some((value, index) => value !== right[index]
    && left.slice(0, index).every((prior, priorIndex) => prior === right[priorIndex])
    && value > right[index])
}
