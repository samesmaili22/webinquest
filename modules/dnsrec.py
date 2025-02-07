import dns.resolver


class DNSRec:
    """
    A class to resolve various DNS record types for a given domain.
    """

    def __init__(self, domain: str) -> None:
        """
        Initialize the DNSRec class with the target domain.

        :param domain: The domain name to resolve.
        """

        self.domain = domain
        self.records = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "SRV", "PTR"]

    def resolve(self) -> dict:
        """
        Resolve the specified DNS records for the given domain.

        :return: A dictionary containing DNS record types as keys and their corresponding resolved values as lists.
        """

        result = {}

        for rec in self.records:
            try:
                answers = dns.resolver.resolve(self.domain, rec)
                result[rec] = [answer.to_text() for answer in answers]
            except dns.resolver.NoAnswer as e:
                result[rec] = e.__str__()  # No record found for this type
            except dns.resolver.LifetimeTimeout as e:
                result[rec] = e.__str__()  # Query timed out
            except dns.resolver.NXDOMAIN as e:
                result[rec] = e.__str__()  # Domain does not exist
            except dns.resolver.NoNameservers as e:
                result[rec] = e.__str__()  # No nameservers found
            except Exception as e:
                result[rec] = e.__str__()  # Catch-all for unexpected errors

        return result
