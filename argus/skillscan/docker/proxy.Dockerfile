FROM mitmproxy/mitmproxy:12.3.1

RUN mkdir -p /var/log/proxy /opt/proxy && chown mitmproxy:mitmproxy /var/log/proxy
# The addon replaces mitmproxy's HTTP/1 error page builder; fail the build if it has moved.
RUN python3 -I -c "import inspect; from mitmproxy.proxy.layers.http import _http1; \
assert callable(_http1.make_error_response); \
assert inspect.getsource(_http1).count('make_error_response(') >= 3"
COPY proxy_addon.py /opt/proxy/proxy_addon.py
COPY proxy_entry.sh /usr/local/bin/proxy_entry.sh
RUN chmod 755 /usr/local/bin/proxy_entry.sh

EXPOSE 8080
# connection_strategy=lazy (set in the entry script) means a refused request never causes DNS or TCP to its host.
ENTRYPOINT ["/usr/local/bin/proxy_entry.sh"]
