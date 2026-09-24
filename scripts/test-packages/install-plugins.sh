set -e

plugins=$(find /tmp -maxdepth 1 -type f -name '*.zip' -print)
for plugin in $plugins; do
  echo "$plugin"
  /usr/share/opensearch-dashboards/bin/opensearch-dashboards-plugin install "file://$plugin"
done

test -n "$plugins"
echo "All plugins installed successfully"
