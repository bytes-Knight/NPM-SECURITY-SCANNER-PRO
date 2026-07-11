# Dependency Confusion Demo Server

Local demo server used to validate the extension against intentionally exposed configs
and lockfiles across multiple ecosystems.

## Ecosystems Covered
- npm
- PyPI
- Maven / Gradle
- RubyGems
- NuGet
- Composer
- Go
- Crates

## Quick Start
```
npm install
npm start
```

Open:
```
http://localhost:3000/
```

## What It Serves
The web root (`public/`) intentionally exposes:
- registry configs (e.g. `.npmrc`, `pip.conf`, `settings.xml`)
- lockfiles and manifests (e.g. `package.json`, `Pipfile.lock`, `Gemfile.lock`, `packages.config`, `go.mod`, `Cargo.toml`)
- `.env` samples for high-risk detection

This data is intentionally unsafe and exists only for testing the extension.
