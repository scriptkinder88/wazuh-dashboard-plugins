set -e

for plugin in \
  /tmp/wazuhCore-*.zip \
  /tmp/wazuhCheckUpdates-*.zip \
  /tmp/wazuh-*.zip
do
  if [ ! -f "$plugin" ]; then
    echo "Expected plugin package not found: $plugin" >&2
    exit 1
  fi

  echo "$plugin"
  /usr/share/opensearch-dashboards/bin/opensearch-dashboards-plugin install "file://$plugin"
done

echo "All plugins installed successfully"
