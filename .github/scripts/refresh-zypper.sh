#!/bin/sh
set -eu

if [ "$1" = tw ] && [ -f /etc/zypp/repos.d/repo-oss.repo ]; then
  # Use the openSUSE CDN for the rolling OSS repository.
  sed -i 's|^baseurl=https\?://download\.opensuse\.org/|baseurl=https://cdn.opensuse.org/|' \
    /etc/zypp/repos.d/repo-oss.repo
fi

status=0
zypper --non-interactive refresh || status=$?
for delay in 5 15; do
  if [ "$status" -eq 0 ]; then
    break
  fi
  printf 'Repository refresh failed with exit code %s. Retrying in %s seconds.\n' "$status" "$delay" >&2
  sleep "$delay"
  status=0
  zypper --non-interactive refresh --force-download || status=$?
done
exit "$status"
