import asyncio
import aiohttp
import warnings
import webtech
import re
from typing import Any
from collections import Counter
from datetime import datetime
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from .sslc import SSLCert
from .dnsrec import DNSRec


# Suppress specific warnings for cleaner output
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=RuntimeWarning)


class WebScanner:
    """
    A web scanning utility that asynchronously scans a list of URLs for various attributes
    such as SSL certificates, technologies, DNS records, common words, and more.

    Attributes:
        url_list (list[str]): List of URLs to scan.
        timeout (float): Timeout for HTTP requests (default: 20 seconds).
        ssl_ports (list[int]): Ports for SSL certificate extraction (optional).
    """

    def __init__(self, url_list: list[str], request_timeout: float = 20.00, ssl_ports: list[int] = None) -> None:
        self.url_list = url_list
        self.timeout = request_timeout
        self.ssl_ports = ssl_ports if ssl_ports else []

    def scan(self) -> list[Any | None]:
        """
        Orchestrates the scanning of all URLs in the `url_list`.

        Returns:
            list[Any | None]: List of scan results, one for each URL.
        """

        # Ensure an asyncio event loop is running
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError as exc:
            if "There is no current event loop in thread" in str(exc):
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop = asyncio.get_event_loop()

        # Create asynchronous tasks for all URLs
        tasks = [asyncio.ensure_future(self.request(url)) for url in self.url_list]
        loop.run_until_complete(asyncio.wait(tasks))

        # Collect results from completed tasks
        scans_result = [task.result() for task in tasks if task.result()]
        return scans_result

    async def request(self, url: str) -> Any | None:
        """
        Performs an asynchronous HTTP GET request to the specified URL.

        Args:
            url (str): The URL to fetch.

        Returns:
            Any | None: The analysis result or None if the request fails.
        """

        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(url=url, verify_ssl=False, timeout=self.timeout) as resp:
                    if resp.status in range(100, 400):
                        return await self.analyze(url, resp)
            except Exception as e:
                print("\n[ ! ]", e)

    async def analyze(self, url, response) -> dict[str, Any]:
        """
        Analyzes the content of a URL, extracting various attributes.
        """

        headers = WebScanner.headers(response)
        homepage, redirect = WebScanner.redirect(response)
        ssl_cert = []

        # Gather SSL certificates if ports are specified
        for port in self.ssl_ports:
            sc = SSLCert(host=urlparse(url).netloc, port=port)
            cert = sc.scan()
            if cert:
                ssl_cert.append({str(port): cert})

        # Handle the homepage URL conversion
        if not isinstance(homepage, str):
            homepage = homepage.__str__()

        # Parse the response content
        content = await response.text()
        links = WebScanner.scrape_links(content, homepage)
        techs = WebScanner.technologies(homepage)
        common_words = WebScanner.common_words(content)
        dns_rec = DNSRec(domain=urlparse(url).netloc)
        domain_records = dns_rec.resolve()

        # Compile the analysis results
        return {
            "datetime": datetime.now().strftime("%b-%d-%Y %H:%M:%S"),
            "homepage": homepage if homepage else "n/a",
            "response_headers": headers if headers else "n/a",
            "redirect_info": redirect if redirect else "n/a",
            "ssl_certificate": ssl_cert if ssl_cert else "n/a",
            "links": links if links else "n/a",
            "technologies": techs if homepage and techs else "n/a",
            "domain_records": domain_records if domain_records else "n/a",
            "common_words": common_words,
        }

    @staticmethod
    def headers(resp) -> dict:
        """
        Extracts headers from the HTTP response.

        Args:
            resp (aiohttp.ClientResponse): The HTTP response object.

        Returns:
            dict: A dictionary of headers.
        """

        return {k: resp.headers.getall(k) for k in resp.headers.keys()}

    @staticmethod
    def redirect(resp) -> tuple[str | Any, list]:
        """
        Extracts redirect information from the HTTP response.

        Args:
            resp (aiohttp.ClientResponse): The HTTP response object.

        Returns:
            tuple[str | Any, list]: Final URL after redirects and a list of redirect details.
        """

        redirects = []
        homepage = resp.url

        if resp.history:
            homepage = str(resp.history[-1].url)

            for history in resp.history:
                redirects.append(
                    {
                        "status": history.status,
                        "url": str(history.url),
                        "response_headers": WebScanner.headers(history),
                    }
                )

        return homepage, redirects

    @staticmethod
    def scrape_links(content: str | bytes, base_url: str) -> list:
        """
        Scrapes internal links from the web page content.

        Args:
            content (str | bytes): The HTML content of the page.
            base_url (str): The base URL for relative links.

        Returns:
            list: A list of internal links.
        """

        soup = BeautifulSoup(content, "html.parser")
        new_urls = set()
        domain_name = urlparse(base_url).netloc

        for tag in soup.find_all("a", href=True):
            href = urljoin(base_url, tag["href"])
            parsed_href = urlparse(href)

            if parsed_href.netloc == domain_name:
                new_urls.add(href)

        return list(new_urls)

    @staticmethod
    def technologies(url: str) -> Any:
        """
        Identifies technologies used by the website.

        Args:
            url (str): The URL to analyze.

        Returns:
            Any: A dictionary of detected technologies.
        """

        wt = webtech.WebTech(options={"json": True})
        report = wt.start_from_url(url)
        return report.get("tech")

    @staticmethod
    def common_words(resp: str) -> list[tuple[str, int]]:
        """
        Identifies the most common words in the page content.

        Args:
            resp (str): The page content.

        Returns:
            list[tuple[str, int]]: A list of the top 10 most common words with their counts.
        """

        soup = BeautifulSoup(resp, "html.parser")
        text = soup.get_text()
        text = re.sub(r"[^\w\s]", "", text.lower())
        words = text.split()
        stopwords = WebScanner.stopwords()
        filtered_words = [word for word in words if word not in stopwords]
        word_counts = Counter(filtered_words)
        return word_counts.most_common(10)

    @staticmethod
    def stopwords() -> list[str]:
        """
        Loads a list of stopwords from a file.

        Returns:
            list[str]: A list of stopwords.
        """

        with open("./modules/stopwords.txt", "r") as file:
            return [line.replace("\n", "") for line in file.readlines()]
