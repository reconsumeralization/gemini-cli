Developer setup and recommended VS Code configuration

Recommended extensions (these are included in `.vscode/extensions.json`):

- ESLint (dbaeumer.vscode-eslint)
- Prettier (esbenp.prettier-vscode)
- Go (golang.go)
- Docker (ms-azuretools.vscode-docker)
- GitLens (eamodio.gitlens)

Quick install (VS Code): open the Extensions view and install the recommended ones.

CLI install examples (macOS/Linux):

```bash
# Install go (if not installed) - platform package managers recommended
# For Debian/Ubuntu:
sudo apt update && sudo apt install -y golang

# Install node/npm (if not installed)
# Debian/Ubuntu example:
sudo apt install -y nodejs npm
```

Run the repository build (top-level):

```bash
npm run build
```

Run the oss-fuzz local compile check (requires Go):

```bash
chmod +x oss-fuzz/gemini_cli/build.sh
OUT=out ./oss-fuzz/gemini_cli/build.sh
```

If you want CI to validate the oss-fuzz build, add a job that runs the above build script.
