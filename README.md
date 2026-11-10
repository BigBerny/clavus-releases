# clavus-releases

Signed release artifacts + auto-update feeds for Clavus Server.app and Clavus.app (desktop).
Binaries only — no source. Feeds: server-latest.json / desktop-latest.json on the latest release.
Published by clavus-server/scripts/release.mjs.

Clavus Server for Linux: the Docker image `ghcr.io/bigberny/clavus-server` is built from each server
release's signed hosted bundle by `.github/workflows/docker-image.yml`. Setup:
https://getclavus.app/install#linux
