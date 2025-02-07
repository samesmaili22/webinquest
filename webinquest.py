import os
import sys
import uuid
import argparse
import json
from modules import WebScanner


class WebInquest:
    """
    WebInquest class handles web scanning tasks, allowing scanning of a single URL
    or multiple URLs from a file.
    """

    def __init__(self, payload: dict) -> None:
        self.url = payload.get("url")
        self.input = payload.get("input")
        self.worker = payload.get("worker")
        self.ssl_ports = payload.get("ssl_ports")

    def start(self):
        """
        Starts the web scanning process based on provided inputs.
        Scans a single URL or multiple URLs from a file using WebScanner.
        """

        result = []

        # Validate SSL ports if provided
        if self.ssl_ports:
            ssl_ports = WebInquest.port_validation(self.ssl_ports)
        else:
            ssl_ports = []

        # Validate worker count
        if self.worker:
            try:
                workers = int(self.worker)
            except Exception:
                print(f"\n[ ! ] Invalid workers count! ({self.worker})\n")
                sys.exit(1)
        else:
            workers = 10  # Default worker count

        # If a single URL is provided, scan it
        if self.url:
            ws = WebScanner(url_list=[self.url], ssl_ports=ssl_ports)
            result.extend(ws.scan())

        # If an input file is provided, read and scan URLs from it
        elif self.input:
            if not os.path.isfile(self.input):
                print(f"\n[ ! ] File not found! ({self.input})\n")
                sys.exit(1)

            file_content = WebInquest.url_file(self.input)
            url_count = len(file_content)
            count = 0

            while count <= url_count:
                url_list = file_content[count : count + workers]
                ws = WebScanner(url_list=url_list)
                result.extend(ws.scan())
                count += workers

        # Save scan results to a JSON file
        WebInquest.output_file({"webinquest": result})

    @staticmethod
    def port_validation(ports: list[str]):
        """
        Validates SSL ports to ensure they are within the valid range (1-65535).

        Args:
            ports (list[str]): List of port numbers as strings.

        Returns:
            list[int]: A list of valid port numbers.
        """

        v_ports = []

        for port in ports:
            try:
                port = int(port)
                if 1 <= port <= 65535:
                    v_ports.append(port)
                else:
                    print(f"\n[ ! ] Invalid port number! ({port})\n")
                    sys.exit(1)
            except Exception:
                print(f"\n[ ! ] Invalid port number! ({port})\n")
                sys.exit(1)

        return v_ports

    @staticmethod
    def output_file(data: dict):
        """
        Saves the scan results to a JSON file with a unique filename.

        Args:
            data (dict): Scan results to be written to the file.
        """

        file_name = "webinquest_" + uuid.uuid4().hex[:8] + ".json"
        with open(file_name, "w") as file:
            json.dump(data, file)

    @staticmethod
    def url_file(file_path: str):
        """
        Reads a file containing URLs and returns them as a list.

        Args:
            file_path (str): Path to the text file containing URLs.

        Returns:
            list[str]: List of URLs extracted from the file.
        """

        with open(file_path, "r") as file:
            return [line.replace("\n", "").strip() for line in file.readlines()]


if __name__ == "__main__":
    # Argument parser setup
    parser = argparse.ArgumentParser()
    parser.usage = "python3 webinquest.py [-u URL] [-i INPUT_FILE] [-w WORKERS] [--ssl-ports PORTS]"
    parser.add_argument("-u", "--url", metavar="", help="A URL, for example: https://google.com")
    parser.add_argument("-i", "--input", metavar="", help="Path to a text file containing URLs")
    parser.add_argument("-w", "--worker", metavar="", help="Number of scan workers (default: 10)")
    parser.add_argument("--ssl-ports", metavar="", nargs="+", help="Ports for SSL certificate extraction")

    # Parse arguments
    args = parser.parse_args()

    # Initialize WebInquest with parsed arguments
    wi = WebInquest(
        payload={
            "url": args.url,
            "input": args.input,
            "worker": args.worker,
            "ssl_ports": args.ssl_ports,
        }
    )
    wi.start()
