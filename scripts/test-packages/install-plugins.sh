set -e

set -- /tmp/*.zip
if [ ! -f "$1" ]; then
  echo "No plugin ZIP packages found in /tmp" >&2
  exit 1
fi

for plugin do
  echo "$plugin"
  /usr/share/opensearch-dashboards/bin/opensearch-dashboards-plugin install "file://$plugin"
done

echo "All plugins installed successfully"
