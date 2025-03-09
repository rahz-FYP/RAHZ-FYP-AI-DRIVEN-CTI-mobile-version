import requests
from mitmproxy import http
import asyncio


def print_color(text, color_code):
    print(f"{color_code}{text}\x1b[0m")

def fetch_blocklist(file_path):
    try:
        with open(file_path, 'r') as file:
            return [line.strip() for line in file.readlines()]
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return []

class My_Proxy_Server:
    def __init__(self, blocked_websites):
        self.blocked_websites = blocked_websites

    def request(self, flow: http.HTTPFlow) -> None:
        print_color(f"Request: {flow.request.pretty_url}", '\x1b[33m')

        if flow.request.method == "GET":
            filename = "get_requests.log"
        elif flow.request.method == "POST":
            filename = "post_requests.log"
        else:
            return

        try:
            with open(filename, 'a') as file:
                file.write(f"URL: {flow.request.pretty_url}\n")

                client_conn_details = {
                    "Address": f"{flow.client_conn.address}",
                    "SNI": flow.client_conn.sni,
                    "ALPN": flow.client_conn.alpn,
                    "TLS Version": flow.client_conn.tls_version,
                }
                file.write(f"Client Connection Details: {client_conn_details}\n")

                server_conn_details = {
                    "Address": f"{flow.server_conn.address}",
                    "SNI": flow.server_conn.sni,
                    "ALPN": flow.server_conn.alpn,
                    "TLS Version": flow.server_conn.tls_version,
                }
                file.write(f"Server Connection Details: {server_conn_details}\n")

                file.write(f"Method: {flow.request.method} {flow.request.http_version}\n")
                file.write("Headers:\n")
                for name, value in flow.request.headers.items():
                    file.write(f"{name}: {value}\n")

                if flow.request.method == "POST":
                    file.write("\nBody:\n\n")

                    encoding = flow.request.headers.get("Content-Encoding", "")
                    print(f"Content-Encoding: {encoding}")  # Debugging line
                    raw_content = flow.request.content
                    file.write(f"{raw_content}")  # Log the raw content for debugging

                file.write("\n\n---\n\n")
        except Exception as e:
            print(f"Error writing to file: {e}")

    def response(self, flow: http.HTTPFlow) -> None:
        if any(website in flow.request.pretty_url for website in self.blocked_websites):
            print_color(f"Response: {flow.response.status_code} - {flow.response.reason}", '\x1b[31m')
        else:
            print_color(f"Response: {flow.response.status_code} - {flow.response.reason}", '\x1b[32m')

async def run_proxy():
    from mitmproxy.tools.web.master import WebMaster
    master = WebMaster(None)

    #blocked_websites = fetch_blocklist(r'S:\Downloads\Blocklist.txt')
    #master.addons.add(My_Proxy_Server(blocked_websites))

    await master.run()

if __name__ == "__main__":
    print("Proxy Server Running:")
    asyncio.run(run_proxy())
